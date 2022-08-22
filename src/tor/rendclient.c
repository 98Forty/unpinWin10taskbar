/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rendclient.c
 * \brief Client code to access location-hidden services.
 **/

#include "or.h"
#include "circpathbias.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "directory.h"
#include "onion_main.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "relay.h"
#include "rendclient.h"
#include "rendcommon.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"
#include "routerset.h"
#include "control.h"

static extend_info_t *rend_client_get_random_intro_impl(
                          const rend_cache_entry_t *rend_query,
                          const int strict, const int warnings);

/** Purge all potentially remotely-detectable state held in the hidden
 * service client code.  Called on SIGNAL NEWNYM. */
void
rend_client_purge_state(void)
{
  rend_cache_purge();
  rend_client_cancel_descriptor_fetches();
  rend_client_purge_last_hid_serv_requests();
}

/** Called when we've established a circuit to an introduction point:
 * send the introduction request. */
void
rend_client_introcirc_has_opened(origin_circuit_t *circ)
{
  tor_assert(circ->base_.purpose == CIRCUIT_PURPOSE_C_INTRODUCING);
  tor_assert(circ->cpath);

  log_info(LD_REND,"introcirc is open");
  connection_ap_attach_pending();
}

/** Send the establish-rendezvous cell along a rendezvous circuit. if
 * it fails, mark the circ for close and return -1. else return 0.
 */
static int
rend_client_send_establish_rendezvous(origin_circuit_t *circ)
{
  tor_assert(circ->base_.purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND);
  tor_assert(circ->rend_data);
  log_info(LD_REND, "Sending an ESTABLISH_RENDEZVOUS cell");

  if (crypto_rand(circ->rend_data->rend_cookie, REND_COOKIE_LEN) < 0) {
    log_warn(LD_BUG, "Internal error: Couldn't produce random cookie.");
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
    return -1;
  }

  /* Set timestamp_dirty, because circuit_expire_building expects it,
   * and the rend cookie also means we've used the circ. */
  circ->base_.timestamp_dirty = time(NULL);

  /* We've attempted to use this circuit. Probe it if we fail */
  pathbias_count_use_attempt(circ);

  if (relay_send_command_from_edge(0, TO_CIRCUIT(circ),
                                   RELAY_COMMAND_ESTABLISH_RENDEZVOUS,
                                   circ->rend_data->rend_cookie,
                                   REND_COOKIE_LEN,
                                   circ->cpath->prev)<0) {
    /* circ is already marked for close */
    log_warn(LD_GENERAL, "Couldn't send ESTABLISH_RENDEZVOUS cell");
    return -1;
  }

  return 0;
}

/** Extend the introduction circuit <b>circ</b> to another valid
 * introduction point for the hidden service it is trying to connect
 * to, or mark it and launch a new circuit if we can't extend it.
 * Return 0 on success or possible success.  Return -1 and mark the
 * introduction circuit for close on permanent failure.
 *
 * On failure, the caller is responsible for marking the associated
 * rendezvous circuit for close. */
static int
rend_client_reextend_intro_circuit(origin_circuit_t *circ)
{
  extend_info_t *extend_info;
  int result;
  extend_info = rend_client_get_random_intro(circ->rend_data);
  if (!extend_info) {
    log_warn(LD_REND,
             "No usable introduction points left for %s. Closing.",
             safe_str_client(circ->rend_data->onion_address));
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_INTERNAL);
    return -1;
  }
  // XXX: should we not re-extend if hs_circ_has_timed_out?
  if (circ->remaining_relay_early_cells) {
    log_info(LD_REND,
             "Re-extending circ %u, this time to %s.",
             (unsigned)circ->base_.n_circ_id,
             safe_str_client(extend_info_describe(extend_info)));
    result = circuit_extend_to_new_exit(circ, extend_info);
  } else {
    log_info(LD_REND,
             "Closing intro circ %u (out of RELAY_EARLY cells).",
             (unsigned)circ->base_.n_circ_id);
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_FINISHED);
    /* connection_ap_handshake_attach_circuit will launch a new intro circ. */
    result = 0;
  }
  extend_info_free(extend_info);
  return result;
}

/** Return true iff we should send timestamps in our INTRODUCE1 cells */
static int
rend_client_should_send_timestamp(void)
{
  if (get_options()->Support022HiddenServices >= 0)
    return get_options()->Support022HiddenServices;

  return networkstatus_get_param(NULL, "Support022HiddenServices", 1, 0, 1);
}

/** Called when we're trying to connect an ap conn; sends an INTRODUCE1 cell
 * down introcirc if possible.
 */
int
rend_client_send_introduction(origin_circuit_t *introcirc,
                              origin_circuit_t *rendcirc)
{
  size_t payload_len;
  int r, v3_shift = 0;
  char payload[RELAY_PAYLOAD_SIZE];
  char tmp[RELAY_PAYLOAD_SIZE];
  rend_cache_entry_t *entry;
  crypt_path_t *cpath;
  off_t dh_offset;
  crypto_pk_t *intro_key = NULL;
  int status = 0;

  tor_assert(introcirc->base_.purpose == CIRCUIT_PURPOSE_C_INTRODUCING);
  tor_assert(rendcirc->base_.purpose == CIRCUIT_PURPOSE_C_REND_READY);
  tor_assert(introcirc->rend_data);
  tor_assert(rendcirc->rend_data);
  tor_assert(!rend_cmp_service_ids(introcirc->rend_data->onion_address,
                                   rendcirc->rend_data->onion_address));
#ifndef NON_ANONYMOUS_MODE_ENABLED
  tor_assert(!(introcirc->build_state->onehop_tunnel));
  tor_assert(!(rendcirc->build_state->onehop_tunnel));
#endif

  if (rend_cache_lookup_entry(introcirc->rend_data->onion_address, -1,
                              &entry) < 1) {
    log_info(LD_REND,
             "query %s didn't have valid rend desc in cache. "
             "Refetching descriptor.",
             safe_str_client(introcirc->rend_data->onion_address));
    rend_client_refetch_v2_renddesc(introcirc->rend_data);
    {
      connection_t *conn;

      while ((conn = connection_get_by_type_state_rendquery(CONN_TYPE_AP,
                       AP_CONN_STATE_CIRCUIT_WAIT,
                       introcirc->rend_data->onion_address))) {
        conn->state = AP_CONN_STATE_RENDDESC_WAIT;
      }
    }

    status = -1;
    goto cleanup;
  }

  /* first 20 bytes of payload are the hash of Bob's pk */
  intro_key = NULL;
  SMARTLIST_FOREACH(entry->parsed->intro_nodes, rend_intro_point_t *,
                    intro, {
    if (tor_memeq(introcirc->build_state->chosen_exit->identity_digest,
                intro->extend_info->identity_digest, DIGEST_LEN)) {
      intro_key = intro->intro_key;
      break;
    }
  });
  if (!intro_key) {
    log_info(LD_REND, "Could not find intro key for %s at %s; we "
             "have a v2 rend desc with %d intro points. "
             "Trying a different intro point...",
             safe_str_client(introcirc->rend_data->onion_address),
             safe_str_client(extend_info_describe(
                                   introcirc->build_state->chosen_exit)),
             smartlist_len(entry->parsed->intro_nodes));

    if (rend_client_reextend_intro_circuit(introcirc)) {
      status = -2;
      goto perm_err;
    } else {
      status = -1;
      goto cleanup;
    }
  }
  if (crypto_pk_get_digest(intro_key, payload)<0) {
    log_warn(LD_BUG, "Internal error: couldn't hash public key.");
    status = -2;
    goto perm_err;
  }

  /* Initialize the pending_final_cpath and start the DH handshake. */
  cpath = rendcirc->build_state->pending_final_cpath;
  if (!cpath) {
    cpath = rendcirc->build_state->pending_final_cpath =
      tor_malloc_zero(sizeof(crypt_path_t));
    cpath->magic = CRYPT_PATH_MAGIC;
    if (!(cpath->rend_dh_handshake_state = crypto_dh_new(DH_TYPE_REND))) {
      log_warn(LD_BUG, "Internal error: couldn't allocate DH.");
      status = -2;
      goto perm_err;
    }
    if (crypto_dh_generate_public(cpath->rend_dh_handshake_state)<0) {
      log_warn(LD_BUG, "Internal error: couldn't generate g^x.");
      status = -2;
      goto perm_err;
    }
  }

  /* If version is 3, write (optional) auth data and timestamp. */
  if (entry->parsed->protocols & (1<<3)) {
    tmp[0] = 3; /* version 3 of the cell format */
    tmp[1] = (uint8_t)introcirc->rend_data->auth_type; /* auth type, if any */
    v3_shift = 1;
    if (introcirc->rend_data->auth_type != REND_NO_AUTH) {
      set_uint16(tmp+2, htons(REND_DESC_COOKIE_LEN));
      memcpy(tmp+4, introcirc->rend_data->descriptor_cookie,
             REND_DESC_COOKIE_LEN);
      v3_shift += 2+REND_DESC_COOKIE_LEN;
    }
    if (rend_client_should_send_timestamp()) {
      uint32_t now = (uint32_t)time(NULL);
      now += 300;
      now -= now % 600;
      set_uint32(tmp+v3_shift+1, htonl(now));
    } else {
      set_uint32(tmp+v3_shift+1, 0);
    }
    v3_shift += 4;
  } /* if version 2 only write version number */
  else if (entry->parsed->protocols & (1<<2)) {
    tmp[0] = 2; /* version 2 of the cell format */
  }

  /* write the remaining items into tmp */
  if (entry->parsed->protocols & (1<<3) || entry->parsed->protocols & (1<<2)) {
    /* version 2 format */
    extend_info_t *extend_info = rendcirc->build_state->chosen_exit;
    int klen;
    /* nul pads */
    set_uint32(tmp+v3_shift+1, tor_addr_to_ipv4h(&extend_info->addr));
    set_uint16(tmp+v3_shift+5, htons(extend_info->port));
    memcpy(tmp+v3_shift+7, extend_info->identity_digest, DIGEST_LEN);
    klen = crypto_pk_asn1_encode(extend_info->onion_key,
                                 tmp+v3_shift+7+DIGEST_LEN+2,
                                 sizeof(tmp)-(v3_shift+7+DIGEST_LEN+2));
    set_uint16(tmp+v3_shift+7+DIGEST_LEN, htons(klen));
    memcpy(tmp+v3_shift+7+DIGEST_LEN+2+klen, rendcirc->rend_data->rend_cookie,
           REND_COOKIE_LEN);
    dh_offset = v3_shift+7+DIGEST_LEN+2+klen+REND_COOKIE_LEN;
  } else {
    /* Version 0. */
    strncpy(tmp, rendcirc->build_state->chosen_exit->nickname,
            (MAX_NICKNAME_LEN+1)); /* nul pads */
    memcpy(tmp+MAX_NICKNAME_LEN+1, rendcirc->rend_data->rend_cookie,
           REND_COOKIE_LEN);
    dh_offset = MAX_NICKNAME_LEN+1+REND_COOKIE_LEN;
  }

  if (crypto_dh_get_public(cpath->rend_dh_handshake_state, tmp+dh_offset,
                           DH_KEY_LEN)<0) {
    log_warn(LD_BUG, "Internal error: couldn't extract g^x.");
    status = -2;
    goto perm_err;
  }

  note_crypto_pk_op(REND_CLIENT);
  /*XXX maybe give crypto_pk_public_hybrid_encrypt a max_len arg,
   * to avoid buffer overflows? */
  r = crypto_pk_public_hybrid_encrypt(intro_key, payload+DIGEST_LEN,
                                      sizeof(payload)-DIGEST_LEN,
                                      tmp,
                                      (int)(dh_offset+DH_KEY_LEN),
                                      PK_PKCS1_OAEP_PADDING, 0);
  if (r<0) {
    log_warn(LD_BUG,"Internal error: hybrid pk encrypt failed.");
    status = -2;
    goto perm_err;
  }

  payload_len = DIGEST_LEN + r;
  tor_assert(payload_len <= RELAY_PAYLOAD_SIZE); /* we overran something */

  /* Copy the rendezvous cookie from rendcirc to introcirc, so that
   * when introcirc gets an ack, we can change the state of the right
   * rendezvous circuit. */
  memcpy(introcirc->rend_data->rend_cookie, rendcirc->rend_data->rend_cookie,
         REND_COOKIE_LEN);

  log_info(LD_REND, "Sending an INTRODUCE1 cell");
  if (relay_send_command_from_edge(0, TO_CIRCUIT(introcirc),
                                   RELAY_COMMAND_INTRODUCE1,
                                   payload, payload_len,
                                   introcirc->cpath->prev)<0) {
    /* introcirc is already marked for close. leave rendcirc alone. */
    log_warn(LD_BUG, "Couldn't send INTRODUCE1 cell");
    status = -2;
    goto cleanup;
  }

  /* Now, we wait for an ACK or NAK on this circuit. */
  circuit_change_purpose(TO_CIRCUIT(introcirc),
                         CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT);
  /* Set timestamp_dirty, because circuit_expire_building expects it
   *