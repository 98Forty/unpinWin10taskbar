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
   * to specify when a circuit entered the _C_INTRODUCE_ACK_WAIT
   * state. */
  introcirc->base_.timestamp_dirty = time(NULL);

  pathbias_count_use_attempt(introcirc);

  goto cleanup;

 perm_err:
  if (!introcirc->base_.marked_for_close)
    circuit_mark_for_close(TO_CIRCUIT(introcirc), END_CIRC_REASON_INTERNAL);
  circuit_mark_for_close(TO_CIRCUIT(rendcirc), END_CIRC_REASON_INTERNAL);
 cleanup:
  memwipe(payload, 0, sizeof(payload));
  memwipe(tmp, 0, sizeof(tmp));

  return status;
}

/** Called when a rendezvous circuit is open; sends a establish
 * rendezvous circuit as appropriate. */
void
rend_client_rendcirc_has_opened(origin_circuit_t *circ)
{
  tor_assert(circ->base_.purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND);

  log_info(LD_REND,"rendcirc is open");

  /* generate a rendezvous cookie, store it in circ */
  if (rend_client_send_establish_rendezvous(circ) < 0) {
    return;
  }
}

/**
 * Called to close other intro circuits we launched in parallel
 * due to timeout.
 */
static void
rend_client_close_other_intros(const char *onion_address)
{
  circuit_t *c;
  /* abort parallel intro circs, if any */
  TOR_LIST_FOREACH(c, circuit_get_global_list(), head) {
    if ((c->purpose == CIRCUIT_PURPOSE_C_INTRODUCING ||
        c->purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT) &&
        !c->marked_for_close && CIRCUIT_IS_ORIGIN(c)) {
      origin_circuit_t *oc = TO_ORIGIN_CIRCUIT(c);
      if (oc->rend_data &&
          !rend_cmp_service_ids(onion_address,
                                oc->rend_data->onion_address)) {
        log_info(LD_REND|LD_CIRC, "Closing introduction circuit %d that we "
                 "built in parallel (Purpose %d).", oc->global_identifier,
                 c->purpose);
        circuit_mark_for_close(c, END_CIRC_REASON_TIMEOUT);
      }
    }
  }
}

/** Called when get an ACK or a NAK for a REND_INTRODUCE1 cell.
 */
int
rend_client_introduction_acked(origin_circuit_t *circ,
                               const uint8_t *request, size_t request_len)
{
  origin_circuit_t *rendcirc;
  (void) request; // XXXX Use this.

  if (circ->base_.purpose != CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT) {
    log_warn(LD_PROTOCOL,
             "Received REND_INTRODUCE_ACK on unexpected circuit %u.",
             (unsigned)circ->base_.n_circ_id);
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_TORPROTOCOL);
    return -1;
  }

  tor_assert(circ->build_state->chosen_exit);
#ifndef NON_ANONYMOUS_MODE_ENABLED
  tor_assert(!(circ->build_state->onehop_tunnel));
#endif
  tor_assert(circ->rend_data);

  /* For path bias: This circuit was used successfully. Valid
   * nacks and acks count. */
  pathbias_mark_use_success(circ);

  if (request_len == 0) {
    /* It's an ACK; the introduction point relayed our introduction request. */
    /* Locate the rend circ which is waiting to hear about this ack,
     * and tell it.
     */
    log_info(LD_REND,"Received ack. Telling rend circ...");
    rendcirc = circuit_get_ready_rend_circ_by_rend_data(circ->rend_data);
    if (rendcirc) { /* remember the ack */
#ifndef NON_ANONYMOUS_MODE_ENABLED
      tor_assert(!(rendcirc->build_state->onehop_tunnel));
#endif
      circuit_change_purpose(TO_CIRCUIT(rendcirc),
                             CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED);
      /* Set timestamp_dirty, because circuit_expire_building expects
       * it to specify when a circuit entered the
       * _C_REND_READY_INTRO_ACKED state. */
      rendcirc->base_.timestamp_dirty = time(NULL);
    } else {
      log_info(LD_REND,"...Found no rend circ. Dropping on the floor.");
    }
    /* close the circuit: we won't need it anymore. */
    circuit_change_purpose(TO_CIRCUIT(circ),
                           CIRCUIT_PURPOSE_C_INTRODUCE_ACKED);
    circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_FINISHED);

    /* close any other intros launched in parallel */
    rend_client_close_other_intros(circ->rend_data->onion_address);
  } else {
    /* It's a NAK; the introduction point didn't relay our request. */
    circuit_change_purpose(TO_CIRCUIT(circ), CIRCUIT_PURPOSE_C_INTRODUCING);
    /* Remove this intro point from the set of viable introduction
     * points. If any remain, extend to a new one and try again.
     * If none remain, refetch the service descriptor.
     */
    log_info(LD_REND, "Got nack for %s from %s...",
        safe_str_client(circ->rend_data->onion_address),
        safe_str_client(extend_info_describe(circ->build_state->chosen_exit)));
    if (rend_client_report_intro_point_failure(circ->build_state->chosen_exit,
                                             circ->rend_data,
                                             INTRO_POINT_FAILURE_GENERIC)>0) {
      /* There are introduction points left. Re-extend the circuit to
       * another intro point and try again. */
      int result = rend_client_reextend_intro_circuit(circ);
      /* XXXX If that call failed, should we close the rend circuit,
       * too? */
      return result;
    }
  }
  return 0;
}

/** The period for which a hidden service directory cannot be queried for
 * the same descriptor ID again. */
#define REND_HID_SERV_DIR_REQUERY_PERIOD (15 * 60)

/** Contains the last request times to hidden service directories for
 * certain queries; each key is a string consisting of the
 * concatenation of a base32-encoded HS directory identity digest, a
 * base32-encoded HS descriptor ID, and a hidden service address
 * (without the ".onion" part); each value is a pointer to a time_t
 * holding the time of the last request for that descriptor ID to that
 * HS directory. */
static strmap_t *last_hid_serv_requests_ = NULL;

/** Returns last_hid_serv_requests_, initializing it to a new strmap if
 * necessary. */
static strmap_t *
get_last_hid_serv_requests(void)
{
  if (!last_hid_serv_requests_)
    last_hid_serv_requests_ = strmap_new();
  return last_hid_serv_requests_;
}

#define LAST_HID_SERV_REQUEST_KEY_LEN (REND_DESC_ID_V2_LEN_BASE32 + \
                                       REND_DESC_ID_V2_LEN_BASE32 + \
                                       REND_SERVICE_ID_LEN_BASE32)

/** Look up the last request time to hidden service directory <b>hs_dir</b>
 * for descriptor ID <b>desc_id_base32</b> for the service specified in
 * <b>rend_query</b>. If <b>set</b> is non-zero,
 * assign the current time <b>now</b> and return that. Otherwise, return
 * the most recent request time, or 0 if no such request has been sent
 * before. */
static time_t
lookup_last_hid_serv_request(routerstatus_t *hs_dir,
                             const char *desc_id_base32,
                             const rend_data_t *rend_query,
                             time_t now, int set)
{
  char hsdir_id_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];
  char hsdir_desc_comb_id[LAST_HID_SERV_REQUEST_KEY_LEN + 1];
  time_t *last_request_ptr;
  strmap_t *last_hid_serv_requests = get_last_hid_serv_requests();
  base32_encode(hsdir_id_base32, sizeof(hsdir_id_base32),
                hs_dir->identity_digest, DIGEST_LEN);
  tor_snprintf(hsdir_desc_comb_id, sizeof(hsdir_desc_comb_id), "%s%s%s",
               hsdir_id_base32,
               desc_id_base32,
               rend_query->onion_address);
  /* XXX023 tor_assert(strlen(hsdir_desc_comb_id) ==
                       LAST_HID_SERV_REQUEST_KEY_LEN); */
  if (set) {
    time_t *oldptr;
    last_request_ptr = tor_malloc_zero(sizeof(time_t));
    *last_request_ptr = now;
    oldptr = strmap_set(last_hid_serv_requests, hsdir_desc_comb_id,
                        last_request_ptr);
    tor_free(oldptr);
  } else
    last_request_ptr = strmap_get_lc(last_hid_serv_requests,
                                     hsdir_desc_comb_id);
  return (last_request_ptr) ? *last_request_ptr : 0;
}

/** Clean the history of request times to hidden service directories, so that
 * it does not contain requests older than REND_HID_SERV_DIR_REQUERY_PERIOD
 * seconds any more. */
static void
directory_clean_last_hid_serv_requests(time_t now)
{
  strmap_iter_t *iter;
  time_t cutoff = now - REND_HID_SERV_DIR_REQUERY_PERIOD;
  strmap_t *last_hid_serv_requests = get_last_hid_serv_requests();
  for (iter = strmap_iter_init(last_hid_serv_requests);
       !strmap_iter_done(iter); ) {
    const char *key;
    void *val;
    time_t *ent;
    strmap_iter_get(iter, &key, &val);
    ent = (time_t *) val;
    if (*ent < cutoff) {
      iter = strmap_iter_next_rmv(last_hid_serv_requests, iter);
      tor_free(ent);
    } else {
      iter = strmap_iter_next(last_hid_serv_requests, iter);
    }
  }
}

/** Remove all requests related to the hidden service named
 * <b>onion_address</b> from the history of times of requests to
 * hidden service directories. */
static void
purge_hid_serv_from_last_hid_serv_requests(const char *onion_address)
{
  strmap_iter_t *iter;
  strmap_t *last_hid_serv_requests = get_last_hid_serv_requests();
  /* XXX023 tor_assert(strlen(onion_address) == REND_SERVICE_ID_LEN_BASE32); */
  for (iter = strmap_iter_init(last_hid_serv_requests);
       !strmap_iter_done(iter); ) {
    const char *key;
    void *val;
    strmap_iter_get(iter, &key, &val);
    /* XXX023 tor_assert(strlen(key) == LAST_HID_SERV_REQUEST_KEY_LEN); */
    if (tor_memeq(key + LAST_HID_SERV_REQUEST_KEY_LEN -
                  REND_SERVICE_ID_LEN_BASE32,
                  onion_address,
                  REND_SERVICE_ID_LEN_BASE32)) {
      iter = strmap_iter_next_rmv(last_hid_serv_requests, iter);
      tor_free(val);
    } else {
      iter = strmap_iter_next(last_hid_serv_requests, iter);
    }
  }
}

/** Purge the history of request times to hidden service directories,
 * so that future lookups of an HS descriptor will not fail because we
 * accessed all of the HSDir relays responsible for the descriptor
 * recently. */
void
rend_client_purge_last_hid_serv_requests(void)
{
  /* Don't create the table if it doesn't exist yet (and it may very
   * well not exist if the user hasn't accessed any HSes)... */
  strmap_t *old_last_hid_serv_requests = last_hid_serv_requests_;
  /* ... and let get_last_hid_serv_requests re-create it for us if
   * necessary. */
  last_hid_serv_requests_ = NULL;

  if (old_last_hid_serv_requests != NULL) {
    log_info(LD_REND, "Purging client last-HS-desc-request-time table");
    strmap_free(old_last_hid_serv_requests, tor_free_);
  }
}

/** Determine the responsible hidden service directories for <b>desc_id</b>
 * and fetch the descriptor with that ID from one of them. Only
 * send a request to a hidden service directory that we have not yet tried
 * during this attempt to connect to this hidden service; on success, return 1,
 * in the case that no hidden service directory is left to ask for the
 * descriptor, return 0, and in case of a failure -1.  */
static int
directory_get_from_hs_dir(const char *desc_id, const rend_data_t *rend_query)
{
  smartlist_t *responsible_dirs = smartlist_new();
  routerstatus_t *hs_dir;
  char desc_id_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];
  time_t now = time(NULL);
  char descriptor_cookie_base64[3*REND_DESC_COOKIE_LEN_BASE64];
  int tor2web_mode = get_options()->Tor2webMode;
  tor_assert(desc_id);
  tor_assert(rend_query);
  /* Determine responsible dirs. Even if we can't get all we want,
   * work with the ones we have. If it's empty, we'll notice below. */
  hid_serv_get_responsible_directories(responsible_dirs, desc_id);

  base32_encode(desc_id_base32, sizeof(desc_id_base32),
                desc_id, DIGEST_LEN);

  /* Only select those hidden service directories to which we did not send
   * a request recently and for which we have a router descriptor here. */

  /* Clean request history first. */
  directory_clean_last_hid_serv_requests(now);

  SMARTLIST_FOREACH(responsible_dirs, routerstatus_t *, dir, {
      time_t last = lookup_last_hid_serv_request(
                            dir, desc_id_base32, rend_query, 0, 0);
      const node_t *node = node_get_by_id(dir->identity_digest);
      if (last + REND_HID_SERV_DIR_REQUERY_PERIOD >= now ||
          !node || !node_has_descriptor(node))
      SMARTLIST_DEL_CURRENT(responsible_dirs, dir);
  });

  hs_dir = smartlist_choose(responsible_dirs);
  smartlist_free(responsible_dirs);
  if (!hs_dir) {
    log_info(LD_REND, "Could not pick one of the responsible hidden "
                      "service directories, because we requested them all "
                      "recently without success.");
    return 0;
  }

  /* Remember that we are requesting a descriptor from this hidden service
   * directory now. */
  lookup_last_hid_serv_request(hs_dir, desc_id_base32, rend_query, now, 1);

  /* Encode descriptor cookie for logging purposes. */
  if (rend_query->auth_type != REND_NO_AUTH) {
    if (base64_encode(descriptor_cookie_base64,
                      sizeof(descriptor_cookie_base64),
                      rend_query->descriptor_cookie, REND_DESC_COOKIE_LEN)<0) {
      log_warn(LD_BUG, "Could not base64-encode descriptor cookie.");
      return 0;
    }
    /* Remove == signs and newline. */
    descriptor_cookie_base64[strlen(descriptor_cookie_base64)-3] = '\0';
  } else {
    strlcpy(descriptor_cookie_base64, "(none)",
            sizeof(descriptor_cookie_base64));
  }

  /* Send fetch request. (Pass query and possibly descriptor cookie so that
   * they can be written to the directory connection and be referred to when
   * the response arrives. */
  directory_initiate_command_routerstatus_rend(hs_dir,
                                          DIR_PURPOSE_FETCH_RENDDESC_V2,
                                          ROUTER_PURPOSE_GENERAL,
                                   tor2web_mode?DIRIND_ONEHOP:DIRIND_ANONYMOUS,
                                          desc_id_base32,
                                          NULL, 0, 0,
                                          rend_query);
  log_info(LD_REND, "Sending fetch request for v2 descriptor for "
                    "service '%s' with descriptor ID '%s', auth type %d, "
                    "and descriptor cookie '%s' to hidden service "
                    "directory %s",
           rend_query->onion_address, desc_id_base32,
           rend_query->auth_type,
           (rend_query->auth_type == REND_NO_AUTH ? "[none]" :
            escaped_safe_str_client(descriptor_cookie_base64)),
           routerstatus_describe(hs_dir));
  control_event_hs_descriptor_requested(rend_query,
                                        hs_dir->identity_digest,
                                        desc_id_base32);
  return 1;
}

/** Unless we already have a descriptor for <b>rend_query</b> with at least
 * one (possibly) working introduction point in it, start a connection to a
 * hidden service directory to fetch a v2 rendezvous service descriptor. */
void
rend_client_refetch_v2_renddesc(const rend_data_t *rend_query)
{
  char descriptor_id[DIGEST_LEN];
  int replicas_left_to_try[REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS];
  int i, tries_left;
  rend_cache_entry_t *e = NULL;
  tor_assert(rend_query);
  /* Are we configured to fetch descriptors? */
  if (!get_options()->FetchHidServDescriptors) {
    log_warn(LD_REND, "We received an onion address for a v2 rendezvous "
        "service descriptor, but are not fetching service descriptors.");
    return;
  }
  /* Before fetching, check if we already have a usable descriptor here. */
  if (rend_cache_lookup_entry(rend_query->onion_address, -1, &e) > 0 &&
      rend_client_any_intro_points_usable(e)) {
    log_info(LD_REND, "We would fetch a v2 rendezvous descriptor, but we "
                      "already have a usable descriptor here. Not fetching.");
    return;
  }
  log_debug(LD_REND, "Fetching v2 rendezvous descriptor for service %s",
            safe_str_client(rend_query->onion_address));
  /* Randomly iterate over the replicas until a descriptor can be fetched
   * from one of the consecutive nodes, or no options are left. */
  tries_left = REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS;
  for (i = 0; i < REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS; i++)
    replicas_left_to_try[i] = i;
  while (tries_left > 0) {
    int rand = crypto_rand_int(tries_left);
    int chosen_replica = replicas_left_to_try[rand];
    replicas_left_to_try[rand] = replicas_left_to_try[--tries_left];

    if (rend_compute_v2_desc_id(descriptor_id, rend_query->onion_address,
                                rend_query->auth_type == REND_STEALTH_AUTH ?
                                    rend_query->descriptor_cookie : NULL,
                                time(NULL), chosen_replica) < 0) {
      log_warn(LD_REND, "Internal error: Computing v2 rendezvous "
                        "descriptor ID did not succeed.");
      /*
       * Hmm, can this write anything to descriptor_id and still fail?
       * Let's clear it just to be safe.
       *
       * From here on, any returns should goto done which clears
       * descriptor_id so we don't leave key-derived material on the stack.
       */
      goto done;
    }
    if (directory_get_from_hs_dir(descriptor_id, rend_query) != 0)
      goto done; /* either success or failure, but we're done */
  }
  /* If we come here, there are no hidden service directories left. */
  log_info(LD_REND, "Could not pick one of the responsible hidden "
                    "service directories to fetch descriptors, because "
                    "we already tried them all unsuccessfully.");
  /* Close pending connections. */
  rend_client_desc_trynow(rend_query->onion_address);

 done:
  memwipe(descriptor_id, 0, sizeof(descriptor_id));

  return;
}

/** Cancel all rendezvous descriptor fetches currently in progress.
 */
void
rend_client_cancel_descriptor_fetches(void)
{
  smartlist_t *connection_array = get_connection_array();

  SMARTLIST_FOREACH_BEGIN(connection_array, connection_t *, conn) {
    if (conn->type == CONN_TYPE_DIR &&
        (conn->purpose == DIR_PURPOSE_FETCH_RENDDESC ||
         conn->purpose == DIR_PURPOSE_FETCH_RENDDESC_V2)) {
      /* It's a rendezvous descriptor fetch in progress -- cancel it
       * by marking the connection for close.
       *
       * Even if this connection has already reached EOF, this is
       * enough to make sure that if the descriptor hasn't been
       * processed yet, it won't be.  See the end of
       * connection_handle_read; connection_reached_eof (indirectly)
       * processes whatever response the connection received. */

      const rend_data_t *rd = (TO_DIR_CONN(conn))->rend_data;
      if (!rd) {
        log_warn(LD_BUG | LD_REND,
                 "Marking for close dir conn fetching rendezvous "
                 "descriptor for unknown service!");
      } else {
        log_debug(LD_REND, "Marking for close dir conn fetching "
                  "rendezvous descriptor for service %s",
                  safe_str(rd->onion_address));
      }
      connection_mark_for_close(conn);
    }
  } SMARTLIST_FOREACH_END(conn);
}

/** Mark <b>failed_intro</b> as a failed introduction point for the
 * hidden service specified by <b>rend_query</b>. If the HS now has no
 * usable intro points, or we do not have an HS descriptor for it,
 * then launch a new renddesc fetch.
 *
 * If <b>failure_type</b> is INTRO_POINT_FAILURE_GENERIC, remove the
 * intro point from (our parsed copy of) the HS descriptor.
 *
 * If <b>failure_type</b> is INTRO_POINT_FAILURE_TIMEOUT, mark the
 * intro point as 'timed out'; it will not be retried until the
 * current hidden service connection attempt has ended or it 