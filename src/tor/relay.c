/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file relay.c
 * \brief Handle relay cell encryption/decryption, plus packaging and
 *    receiving from circuits, plus queuing on circuits.
 **/

#define RELAY_PRIVATE
#include "or.h"
#include "addressmap.h"
#include "buffers.h"
#include "channel.h"
#include "circpathbias.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "connection_or.h"
#include "control.h"
#include "geoip.h"
#include "onion_main.h"
#include "mempool.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "onion.h"
#include "policies.h"
#include "reasons.h"
#include "relay.h"
#include "rendcommon.h"
#include "router.h"
#include "routerlist.h"
#include "routerparse.h"

static edge_connection_t *relay_lookup_conn(circuit_t *circ, cell_t *cell,
                                            cell_direction_t cell_direction,
                                            crypt_path_t *layer_hint);

static int connection_edge_process_relay_cell(cell_t *cell, circuit_t *circ,
                                              edge_connection_t *conn,
                                              crypt_path_t *layer_hint);
static void circuit_consider_sending_sendme(circuit_t *circ,
                                            crypt_path_t *layer_hint);
static void circuit_resume_edge_reading(circuit_t *circ,
                                        crypt_path_t *layer_hint);
static int circuit_resume_edge_reading_helper(edge_connection_t *conn,
                                              circuit_t *circ,
                                              crypt_path_t *layer_hint);
static int circuit_consider_stop_edge_reading(circuit_t *circ,
                                              crypt_path_t *layer_hint);
static int circuit_queue_streams_are_blocked(circuit_t *circ);
static void adjust_exit_policy_from_exitpolicy_failure(origin_circuit_t *circ,
                                                  entry_connection_t *conn,
                                                  node_t *node,
                                                  const tor_addr_t *addr);
#if 0
static int get_max_middle_cells(void);
#endif

/** Stop reading on edge connections when we have this many cells
 * waiting on the appropriate queue. */
#define CELL_QUEUE_HIGHWATER_SIZE 256
/** Start reading from edge connections again when we get down to this many
 * cells. */
#define CELL_QUEUE_LOWWATER_SIZE 64

/** Stats: how many relay cells have originated at this hop, or have
 * been relayed onward (not recognized at this hop)?
 */
uint64_t stats_n_relay_cells_relayed = 0;
/** Stats: how many relay cells have been delivered to streams at this
 * hop?
 */
uint64_t stats_n_relay_cells_delivered = 0;

/** Used to tell which stream to read from first on a circuit. */
static tor_weak_rng_t stream_choice_rng = TOR_WEAK_RNG_INIT;

/** Update digest from the payload of cell. Assign integrity part to
 * cell.
 */
static void
relay_set_digest(crypto_digest_t *digest, cell_t *cell)
{
  char integrity[4];
  relay_header_t rh;

  crypto_digest_add_bytes(digest, (char*)cell->payload, CELL_PAYLOAD_SIZE);
  crypto_digest_get_digest(digest, integrity, 4);
//  log_fn(LOG_DEBUG,"Putting digest of %u %u %u %u into relay cell.",
//    integrity[0], integrity[1], integrity[2], integrity[3]);
  relay_header_unpack(&rh, cell->payload);
  memcpy(rh.integrity, integrity, 4);
  relay_header_pack(cell->payload, &rh);
}

/** Does the digest for this circuit indicate that this cell is for us?
 *
 * Update digest from the payload of cell (with the integrity part set
 * to 0). If the integrity part is valid, return 1, else restore digest
 * and cell to their original state and return 0.
 */
static int
relay_digest_matches(crypto_digest_t *digest, cell_t *cell)
{
  char received_integrity[4], calculated_integrity[4];
  relay_header_t rh;
  crypto_digest_t *backup_digest=NULL;

  backup_digest = crypto_digest_dup(digest);

  relay_header_unpack(&rh, cell->payload);
  memcpy(received_integrity, rh.integrity, 4);
  memset(rh.integrity, 0, 4);
  relay_header_pack(cell->payload, &rh);

//  log_fn(LOG_DEBUG,"Reading digest of %u %u %u %u from relay cell.",
//    received_integrity[0], received_integrity[1],
//    received_integrity[2], received_integrity[3]);

  crypto_digest_add_bytes(digest, (char*) cell->payload, CELL_PAYLOAD_SIZE);
  crypto_digest_get_digest(digest, calculated_integrity, 4);

  if (tor_memneq(received_integrity, calculated_integrity, 4)) {
//    log_fn(LOG_INFO,"Recognized=0 but bad digest. Not recognizing.");
// (%d vs %d).", received_integrity, calculated_integrity);
    /* restore digest to its old form */
    crypto_digest_assign(digest, backup_digest);
    /* restore the relay header */
    memcpy(rh.integrity, received_integrity, 4);
    relay_header_pack(cell->payload, &rh);
    crypto_digest_free(backup_digest);
    return 0;
  }
  crypto_digest_free(backup_digest);
  return 1;
}

/** Apply <b>cipher</b> to CELL_PAYLOAD_SIZE bytes of <b>in</b>
 * (in place).
 *
 * If <b>encrypt_mode</b> is 1 then encrypt, else decrypt.
 *
 * Return -1 if the crypto fails, else return 0.
 */
static int
relay_crypt_one_payload(crypto_cipher_t *cipher, uint8_t *in,
                        int encrypt_mode)
{
  int r;
  (void)encrypt_mode;
  r = crypto_cipher_crypt_inplace(cipher, (char*) in, CELL_PAYLOAD_SIZE);

  if (r) {
    log_warn(LD_BUG,"Error during relay encryption");
    return -1;
  }
  return 0;
}

/** Receive a relay cell:
 *  - Crypt it (encrypt if headed toward the origin or if we <b>are</b> the
 *    origin; decrypt if we're headed toward the exit).
 *  - Check if recognized (if exitward).
 *  - If recognized and the digest checks out, then find if there's a stream
 *    that the cell is intended for, and deliver it to the right
 *    connection_edge.
 *  - If not recognized, then we need to relay it: append it to the appropriate
 *    cell_queue on <b>circ</b>.
 *
 * Return -<b>reason</b> on failure.
 */
int
circuit_receive_relay_cell(cell_t *cell, circuit_t *circ,
                           cell_direction_t cell_direction)
{
  channel_t *chan = NULL;
  crypt_path_t *layer_hint=NULL;
  char recognized=0;
  int reason;

  tor_assert(cell);
  tor_assert(circ);
  tor_assert(cell_direction == CELL_DIRECTION_OUT ||
             cell_direction == CELL_DIRECTION_IN);
  if (circ->marked_for_close)
    return 0;

  if (relay_crypt(circ, cell, cell_direction, &layer_hint, &recognized) < 0) {
    log_warn(LD_BUG,"relay crypt failed. Dropping connection.");
    return -END_CIRC_REASON_INTERNAL;
  }

  if (recognized) {
    edge_connection_t *conn = NULL;

    if (circ->purpose == CIRCUIT_PURPOSE_PATH_BIAS_TESTING) {
      pathbias_check_probe_response(circ, cell);

      /* We need to drop this cell no matter what to avoid code that expects
       * a certain purpose (such as the hidserv code). */
      return 0;
    }

    conn = relay_lookup_conn(circ, cell, cell_direction,
                                                layer_hint);
    if (cell_direction == CELL_DIRECTION_OUT) {
      ++stats_n_relay_cells_delivered;
      log_debug(LD_OR,"Sending away from origin.");
      if ((reason=connection_edge_process_relay_cell(cell, circ, conn, NULL))
          < 0) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "connection_edge_process_relay_cell (away from origin) "
               "failed.");
        return reason;
      }
    }
    if (cell_direction == CELL_DIRECTION_IN) {
      ++stats_n_relay_cells_delivered;
      log_debug(LD_OR,"Sending to origin.");
      if ((reason = connection_edge_process_relay_cell(cell, circ, conn,
                                                       layer_hint)) < 0) {
        log_warn(LD_OR,
                 "connection_edge_process_relay_cell (at origin) failed.");
        return reason;
      }
    }
    return 0;
  }

  /* not recognized. pass it on. */
  if (cell_direction == CELL_DIRECTION_OUT) {
    cell->circ_id = circ->n_circ_id; /* switch it */
    chan = circ->n_chan;
  } else if (! CIRCUIT_IS_ORIGIN(circ)) {
    cell->circ_id = TO_OR_CIRCUIT(circ)->p_circ_id; /* switch it */
    chan = TO_OR_CIRCUIT(circ)->p_chan;
  } else {
    log_fn(LOG_PROTOCOL_WARN, LD_OR,
           "Dropping unrecognized inbound cell on origin circuit.");
    /* If we see unrecognized cells on path bias testing circs,
     * it's bad mojo. Those circuits need to die.
     * XXX: Shouldn't they always die? */
    if (circ->purpose == CIRCUIT_PURPOSE_PATH_BIAS_TESTING) {
      TO_ORIGIN_CIRCUIT(circ)->path_state = PATH_STATE_USE_FAILED;
      return -END_CIRC_REASON_TORPROTOCOL;
    } else {
      return 0;
    }
  }

  if (!chan) {
    // XXXX Can this splice stuff be done more cleanly?
    if (! CIRCUIT_IS_ORIGIN(circ) &&
        TO_OR_CIRCUIT(circ)->rend_splice &&
        cell_direction == CELL_DIRECTION_OUT) {
      or_circuit_t *splice = TO_OR_CIRCUIT(circ)->rend_splice;
      tor_assert(circ->purpose == CIRCUIT_PURPOSE_REND_ESTABLISHED);
      tor_assert(splice->base_.purpose == CIRCUIT_PURPOSE_REND_ESTABLISHED);
      cell->circ_id = splice->p_circ_id;
      cell->command = CELL_RELAY; /* can't be relay_early anyway */
      if ((reason = circuit_receive_relay_cell(cell, TO_CIRCUIT(splice),
                                               CELL_DIRECTION_IN)) < 0) {
        log_warn(LD_REND, "Error relaying cell across rendezvous; closing "
                 "circuits");
        /* XXXX Do this here, or just return -1? */
        circuit_mark_for_close(circ, -reason);
        return reason;
      }
      return 0;
    }
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Didn't recognize cell, but circ stops here! Closing circ.");
    return -END_CIRC_REASON_TORPROTOCOL;
  }

  log_debug(LD_OR,"Passing on unrecognized cell.");

  ++stats_n_relay_cells_relayed; /* XXXX no longer quite accurate {cells}
                                  * we might kill the circ before we relay
                                  * the cells. */

  append_cell_to_circuit_queue(circ, chan, cell, cell_direction, 0);
  return 0;
}

/** Do the appropriate en/decryptions for <b>cell</b> arriving on
 * <b>circ</b> in direction <b>cell_direction</b>.
 *
 * If cell_direction == CELL_DIRECTION_IN:
 *   - If we're at the origin (we're the OP), for hops 1..N,
 *     decrypt cell. If recognized, stop.
 *   - Else (we're not the OP), encrypt one hop. Cell is not recognized.
 *
 * If cell_direction == CELL_DIRECTION_OUT:
 *   - decrypt one hop. Check if recognized.
 *
 * If cell is recognized, set *recognized to 1, and set
 * *layer_hint to the hop that recognized it.
 *
 * Return -1 to indicate that we should mark the circuit for close,
 * else return 0.
 */
int
relay_crypt(circuit_t *circ, cell_t *cell, cell_direction_t cell_direction,
            crypt_path_t **layer_hint, char *recognized)
{
  relay_header_t rh;

  tor_assert(circ);
  tor_assert(cell);
  tor_assert(recognized);
  tor_assert(cell_direction == CELL_DIRECTION_IN ||
             cell_direction == CELL_DIRECTION_OUT);

  if (cell_direction == CELL_DIRECTION_IN) {
    if (CIRCUIT_IS_ORIGIN(circ)) { /* We're at the beginning of the circuit.
                                    * We'll want to do layered decrypts. */
      crypt_path_t *thishop, *cpath = TO_ORIGIN_CIRCUIT(circ)->cpath;
      thishop = cpath;
      if (thishop->state != CPATH_STATE_OPEN) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Relay cell before first created cell? Closing.");
        return -1;
      }
      do { /* Remember: cpath is in forward order, that is, first hop first. */
        tor_assert(thishop);

        if (relay_crypt_one_payload(thishop->b_crypto, cell->payload, 0) < 0)
          return -1;

        relay_header_unpack(&rh, cell->payload);
        if (rh.recognized == 0) {
          /* it's possibly recognized. have to check digest to be sure. */
          if (relay_digest_matches(thishop->b_digest, cell)) {
            *recognized = 1;
            *layer_hint = thishop;
            return 0;
          }
        }

        thishop = thishop->next;
      } while (thishop != cpath && thishop->state == CPATH_STATE_OPEN);
      log_fn(LOG_PROTOCOL_WARN, LD_OR,
             "Incoming cell at client not recognized. Closing.");
      return -1;
    } else { /* we're in the middle. Just one crypt. */
      if (relay_crypt_one_payload(TO_OR_CIRCUIT(circ)->p_crypto,
                                  cell->payload, 1) < 0)
        return -1;
//      log_fn(LOG_DEBUG,"Skipping recognized check, because we're not "
//             "the client.");
    }
  } else /* cell_direction == CELL_DIRECTION_OUT */ {
    /* we're in the middle. Just one crypt. */

    if (relay_crypt_one_payload(TO_OR_CIRCUIT(circ)->n_crypto,
                                cell->payload, 0) < 0)
      return -1;

    relay_header_unpack(&rh, cell->payload);
    if (rh.recognized == 0) {
      /* it's possibly recognized. have to check digest to be sure. */
      if (relay_digest_matches(TO_OR_CIRCUIT(circ)->n_digest, cell)) {
        *recognized = 1;
        return 0;
      }
    }
  }
  return 0;
}

/** Package a relay cell from an edge:
 *  - Encrypt it to the right layer
 *  - Append it to the appropriate cell_queue on <b>circ</b>.
 */
static int
circuit_package_relay_cell(cell_t *cell, circuit_t *circ,
                           cell_direction_t cell_direction,
                           crypt_path_t *layer_hint, streamid_t on_stream,
                           const char *filename, int lineno)
{
  channel_t *chan; /* where to send the cell */

  if (cell_direction == CELL_DIRECTION_OUT) {
    crypt_path_t *thishop; /* counter for repeated crypts */
    chan = circ->n_chan;
    if (!chan) {
      log_warn(LD_BUG,"outgoing relay cell sent from %s:%d has n_chan==NULL."
               " Dropping.", filename, lineno);
      return 0; /* just drop it */
    }
    if (!CIRCUIT_IS_ORIGIN(circ)) {
      log_warn(LD_BUG,"outgoing relay cell sent from %s:%d on non-origin "
               "circ. Dropping.", filename, lineno);
      return 0; /* just drop it */
    }

    relay_set_digest(layer_hint->f_digest, cell);

    thishop = layer_hint;
    /* moving from farthest to nearest hop */
    do {
      tor_assert(thishop);
      /* XXXX RD This is a bug, right? */
      log_debug(LD_OR,"crypting a layer of the relay cell.");
      if (relay_crypt_one_payload(thishop->f_crypto, cell->payload, 1) < 0) {
        return -1;
      }

      thishop = thishop->prev;
    } while (thishop != TO_ORIGIN_CIRCUIT(circ)->cpath->prev);

  } else { /* incoming cell */
    or_circuit_t *or_circ;
    if (CIRCUIT_IS_ORIGIN(circ)) {
      /* We should never package an _incoming_ cell from the circuit
       * origin; that means we messed up somewhere. */
      log_warn(LD_BUG,"incoming relay cell at origin circuit. Dropping.");
      assert_circuit_ok(circ);
      return 0; /* just drop it */
    }
    or_circ = TO_OR_CIRCUIT(circ);
    chan = or_circ->p_chan;
    relay_set_digest(or_circ->p_digest, cell);
    if (relay_crypt_one_payload(or_circ->p_crypto, cell->payload, 1) < 0)
      return -1;
  }
  ++stats_n_relay_cells_relayed;

  append_cell_to_circuit_queue(circ, chan, cell, cell_direction, on_stream);
  return 0;
}

/** If cell's stream_id matches the stream_id of any conn that's
 * attached to circ, return that conn, else return NULL.
 */
static edge_connection_t *
relay_lookup_conn(circuit_t *circ, cell_t *cell,
                  cell_direction_t cell_direction, crypt_path_t *layer_hint)
{
  edge_connection_t *tmpconn;
  relay_header_t rh;

  relay_header_unpack(&rh, cell->payload);

  if (!rh.stream_id)
    return NULL;

  /* IN or OUT cells could have come from either direction, now
   * that we allow rendezvous *to* an OP.
   */

  if (CIRCUIT_IS_ORIGIN(circ)) {
    for (tmpconn = TO_ORIGIN_CIRCUIT(circ)->p_streams; tmpconn;
         tmpconn=tmpconn->next_stream) {
      if (rh.stream_id == tmpconn->stream_id &&
          !tmpconn->base_.marked_for_close &&
          tmpconn->cpath_layer == layer_hint) {
        log_debug(LD_APP,"found conn for stream %d.", rh.stream_id);
        return tmpconn;
      }
    }
  } else {
    for (tmpconn = TO_OR_CIRCUIT(circ)->n_streams; tmpconn;
         tmpconn=tmpconn->next_stream) {
      if (rh.stream_id == tmpconn->stream_id &&
          !tmpconn->base_.marked_for_close) {
        log_debug(LD_EXIT,"found conn for stream %d.", rh.stream_id);
        if (cell_direction == CELL_DIRECTION_OUT ||
            connection_edge_is_rendezvous_stream(tmpconn))
          return tmpconn;
      }
    }
    for (tmpconn = TO_OR_CIRCUIT(circ)->resolving_streams; tmpconn;
         tmpconn=tmpconn->next_stream) {
      if (rh.stream_id == tmpconn->stream_id &&
          !tmpconn->base_.marked_for_close) {
        log_debug(LD_EXIT,"found conn for stream %d.", rh.stream_id);
        return tmpconn;
      }
    }
  }
  return NULL; /* probably a begin relay cell */
}

/** Pack the relay_header_t host-order structure <b>src</b> into
 * network-order in the buffer <b>dest</b>. See tor-spec.txt for details
 * about the wire format.
 */
void
relay_header_pack(uint8_t *dest, const relay_header_t *src)
{
  set_uint8(dest, src->command);
  set_uint16(dest+1, htons(src->recognized));
  set_uint16(dest+3, htons(src->stream_id));
  memcpy(dest+5, src->integrity, 4);
  set_uint16(dest+9, htons(src->length));
}

/** Unpack the network-order buffer <b>src</b> into a host-order
 * relay_header_t structure <b>dest</b>.
 */
void
relay_header_unpack(relay_header_t *dest, const uint8_t *src)
{
  dest->command = get_uint8(src);
  dest->recognized = ntohs(get_uint16(src+1));
  dest->stream_id = ntohs(get_uint16(src+3));
  memcpy(dest->integrity, src+5, 4);
  dest->length = ntohs(get_uint16(src+9));
}

/** Convert the relay <b>command</b> into a human-readable string. */
static const char *
relay_command_to_string(uint8_t command)
{
  switch (command) {
    case RELAY_COMMAND_BEGIN: return "BEGIN";
    case RELAY_COMMAND_DATA: return "DATA";
    case RELAY_COMMAND_END: return "END";
    case RELAY_COMMAND_CONNECTED: return "CONNECTED";
    case RELAY_COMMAND_SENDME: return "SENDME";
    case RELAY_COMMAND_EXTEND: return "EXTEND";
    case RELAY_COMMAND_EXTENDED: return "EXTENDED";
    case RELAY_COMMAND_TRUNCATE: return "TRUNCATE";
    case RELAY_COMMAND_TRUNCATED: return "TRUNCATED";
    case RELAY_COMMAND_DROP: return "DROP";
    case RELAY_COMMAND_RESOLVE: return "RESOLVE";
    case RELAY_COMMAND_RESOLVED: return "RESOLVED";
    case RELAY_COMMAND_BEGIN_DIR: return "BEGIN_DIR";
    case RELAY_COMMAND_ESTABLISH_INTRO: return "ESTABLISH_INTRO";
    case RELAY_COMMAND_ESTABLISH_RENDEZVOUS: return "ESTABLISH_RENDEZVOUS";
    case RELAY_COMMAND_INTRODUCE1: return "INTRODUCE1";
    case RELAY_COMMAND_INTRODUCE2: return "INTRODUCE2";
    case RELAY_COMMAND_RENDEZVOUS1: return "RENDEZVOUS1";
    case RELAY_COMMAND_RENDEZVOUS2: return "RENDEZVOUS2";
    case RELAY_COMMAND_INTRO_ESTABLISHED: return "INTRO_ESTABLISHED";
    case RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
      return "RENDEZVOUS_ESTABLISHED";
    case RELAY_COMMAND_INTRODUCE_ACK: return "INTRODUCE_ACK";
    default: return "(unrecognized)";
  }
}

/** Make a relay cell out of <b>relay_command</b> and <b>payload</b>, and send
 * it onto the open circuit <b>circ</b>. <b>stream_id</b> is the ID on
 * <b>circ</b> for the stream that's sending the relay cell, or 0 if it's a
 * control cell.  <b>cpath_layer</b> is NULL for OR->OP cells, or the
 * destination hop for OP->OR cells.
 *
 * If you can't send the cell, mark the circuit for close and return -1. Else
 * return 0.
 */
int
relay_send_command_from_edge_(streamid_t stream_id, circuit_t *circ,
                              uint8_t relay_command, const char *payload,
                              size_t payload_len, crypt_path_t *cpath_layer,
                              const char *filename, int lineno)
{
  cell_t cell;
  relay_header_t rh;
  cell_direction_t cell_direction;
  /* XXXX NM Split this function into a separate versions per circuit type? */

  tor_assert(circ);
  tor_assert(payload_len <= RELAY_PAYLOAD_SIZE);

  memset(&cell, 0, sizeof(cell_t));
  cell.command = CELL_RELAY;
  if (cpath_layer) {
    cell.circ_id = circ->n_circ_id;
    cell_direction = CELL_DIRECTION_OUT;
  } else if (! CIRCUIT_IS_ORIGIN(circ)) {
    cell.circ_id = TO_OR_CIRCUIT(circ)->p_circ_id;
    cell_direction = CELL_DIRECTION_IN;
  } else {
    return -1;
  }

  memset(&rh, 0, sizeof(rh));
  rh.command = relay_command;
  rh.stream_id = stream_id;
  rh.length = payload_len;
  relay_header_pack(cell.payload, &rh);
  if (payload_len)
    memcpy(cell.payload+RELAY_HEADER_SIZE, payload, payload_len);

  log_debug(LD_OR,"delivering %d cell %s.", relay_command,
            cell_direction == CELL_DIRECTION_OUT ? "forward" : "backward");

  /* If we are sending an END cell and this circuit is used for a tunneled
   * directory request, advance its state. */
  if (relay_command == RELAY_COMMAND_END && circ->dirreq_id)
    geoip_change_dirreq_state(circ->dirreq_id, DIRREQ_TUNNELED,
                              DIRREQ_END_CELL_SENT);

  if (cell_direction == CELL_DIRECTION_OUT && circ->n_chan) {
    /* if we're using relaybandwidthrate, this conn wants priority */
    channel_timestamp_client(circ->n_chan);
  }

  if (cell_direction == CELL_DIRECTION_OUT) {
    origin_circuit_t *origin_circ = TO_ORIGIN_CIRCUIT(circ);
    if (origin_circ->remaining_relay_early_cells > 0 &&
        (relay_command == RELAY_COMMAND_EXTEND ||
         relay_command == RELAY_COMMAND_EXTEND2 ||
         cpath_layer != origin_circ->cpath)) {
      /* If we've got any relay_early cells left and (we're sending
       * an extend cell or we're not talking to the first hop), use
       * one of them.  Don't worry about the conn protocol version:
       * append_cell_to_circuit_queue will fix it up. */
      cell.command = CELL_RELAY_EARLY;
      --origin_circ->remaining_relay_early_cells;
      log_debug(LD_OR, "Sending a RELAY_EARLY cell; %d remaining.",
                (int)origin_circ->remaining_relay_early_cells);
      /* Memorize the command that is sent as RELAY_EARLY cell; helps debug
       * task 878. */
      origin_circ->relay_early_commands[
          origin_circ->relay_early_cells_sent++] = relay_command;
    } else if (relay_command == RELAY_COMMAND_EXTEND ||
               relay_command == RELAY_COMMAND_EXTEND2) {
      /* If no RELAY_EARLY cells can be sent over this circuit, log which
       * commands have been sent as RELAY_EARLY cells before; helps debug
       * task 878. */
      smartlist_t *commands_list = smartlist_new();
      int i = 0;
      char *commands = NULL;
      for (; i < origin_circ->relay_early_cells_sent; i++)
        smartlist_add(commands_list, (char *)
            relay_command_to_string(origin_circ->relay_early_commands[i]));
      commands = smartlist_join_strings(commands_list, ",", 0, NULL);
      log_warn(LD_BUG, "Uh-oh.  We're sending a RELAY_COMMAND_EXTEND cell, "
               "but we have run out of RELAY_EARLY cells on that circuit. "
               "Commands sent before: %s", commands);
      tor_free(commands);
      smartlist_free(commands_list);
    }
  }

  if (circuit_package_relay_cell(&cell, circ, cell_direction, cpath_layer,
                                 stream_id, filename, lineno) < 0) {
    log_warn(LD_BUG,"circuit_package_relay_cell failed. Closing.");
    circuit_mark_for_close(circ, END_CIRC_REASON_INTERNAL);
    return -1;
  }
  return 0;
}

/** Make a relay cell out of <b>relay_command</b> and <b>payload</b>, and
 * send it onto the open circuit <b>circ</b>. <b>fromconn</b> is the stream
 * that's sending the relay cell, or NULL if it's a control cell.
 * <b>cpath_layer</b> is NULL for OR->OP cells, or the destination hop
 * for OP->OR cells.
 *
 * If you can't send the cell, mark the circuit for close and
 * return -1. Else return 0.
 */
int
connection_edge_send_command(edge_connection_t *fromconn,
                             uint8_t relay_command, const char *payload,
                             size_t payload_len)
{
  /* XXXX NM Split this function into a separate versions per circuit type? */
  circuit_t *circ;
  crypt_path_t *cpath_layer = fromconn->cpath_layer;
  tor_assert(fromconn);
  circ = fromconn->on_circuit;

  if (fromconn->base_.marked_for_close) {
    log_warn(LD_BUG,
             "called on conn that's already marked for close at %s:%d.",
             fromconn->base_.marked_for_close_file,
             fromconn->base_.marked_for_close);
    return 0;
  }

  if (!circ) {
    if (fromconn->base_.type == CONN_TYPE_AP) {
      log_info(LD_APP,"no circ. Closing conn.");
      connection_mark_unattached_ap(EDGE_TO_ENTRY_CONN(fromconn),
                                    END_STREAM_REASON_INTERNAL);
    } else {
      log_info(LD_EXIT,"no circ. Closing conn.");
      fromconn->edge_has_sent_end = 1; /* no circ to send to */
      fromconn->end_reason = END_STREAM_REASON_INTERNAL;
      connection_mark_for_close(TO_CONN(fromconn));
    }
    return -1;
  }

  return relay_send_command_from_edge(fromconn->stream_id, circ,
                                      relay_command, payload,
                                      payload_len, cpath_layer);
}

/** How many times will I retry a stream that fails due to DNS
 * resolve failure or misc error?
 */
#define MAX_RESOLVE_FAILURES 3

/** Return 1 if reason is something that you should retry if you
 * get the end cell before you've connected; else return 0. */
static int
edge_reason_is_retriable(int reason)
{
  return reason == END_STREAM_REASON_HIBERNATING ||
         reason == END_STREAM_REASON_RESOURCELIMIT ||
         reason == END_STREAM_REASON_EXITPOLICY ||
         reason == END_STREAM_REASON_RESOLVEFAILED ||
         reason == END_STREAM_REASON_MISC ||
         reason == END_STREAM_REASON_NOROUTE;
}

/** Called when we receive an END cell on a stream that isn't open yet,
 * from the client side.
 * Arguments are as for connection_edge_process_relay_cell().
 */
static int
connection_ap_process_end_not_open(
    relay_header_t *rh, cell_t *cell, origin_circuit_t *circ,
    entry_connection_t *conn, crypt_path_t *layer_hint)
{
  node_t *exitrouter;
  int reason = *(cell->payload+RELAY_HEADER_SIZE);
  int control_reason;
  edge_connection_t *edge_conn = ENTRY_TO_EDGE_CONN(conn);
  (void) layer_hint; /* unused */

  if (rh->length > 0) {
    if (reason == END_STREAM_REASON_TORPROTOCOL ||
        reason == END_STREAM_REASON_INTERNAL ||
        reason == END_STREAM_REASON_DESTROY) {
      /* All three of these reasons could mean a failed tag
       * hit the exit and it complained. Do not probe.
       * Fail the circuit. */
      circ->path_state = PATH_STATE_USE_FAILED;
      return -END_CIRC_REASON_TORPROTOCOL;
    } else {
      /* Path bias: If we get a valid reason code from the exit,
       * it wasn't due to tagging.
       *
       * We rely on recognized+digest being strong enough to make
       * tags unlikely to allow us to get tagged, yet 'recognized'
       * reason codes here. */
      pathbias_mark_use_success(circ);
    }
  }

  if (rh->length == 0) {
    reason = END_STREAM_REASON_MISC;
  }

  control_reason = reason | END_STREAM_REASON_FLAG_REMOTE;

  if (edge_reason_is_retriable(reason) &&
      /* avoid retry if rend */
      !connection_edge_is_rendezvous_stream(edge_conn)) {
    const char *chosen_exit_digest =
      circ->build_state->chosen_exit->identity_digest;
    log_info(LD_APP,"Address '%s' refused due to '%s'. Considering retrying.",
             safe_str(conn->socks_request->address),
             stream_end_reason_to_string(reason));
    exitrouter = node_get_mutable_by_id(chosen_exit_digest);
    switch (reason) {
      case END_STREAM_REASON_EXITPOLICY: {
        tor_addr_t addr;
        tor_addr_make_unspec(&addr);
        if (rh->length >= 5) {
          int ttl = -1;
          tor_addr_make_unspec(&addr);
          if (rh->length == 5 || rh->length == 9) {
            tor_addr_from_ipv4n(&addr,
                                get_uint32(cell->payload+RELAY_HEADER_SIZE+1));
            if (rh->length == 9)
              ttl = (int)ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE+5));
          } else if (rh->length == 17 || rh->length == 21) {
            tor_addr_from_ipv6_bytes(&addr,
                                (char*)(cell->payload+RELAY_HEADER_SIZE+1));
            if (rh->length == 21)
              ttl = (int)ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE+17));
          }
          if (tor_addr_is_null(&addr)) {
            log_info(LD_APP,"Address '%s' resolved to 0.0.0.0. Closing,",
                     safe_str(conn->socks_request->address));
            connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
            return 0;
          }

          if ((tor_addr_family(&addr) == AF_INET && !conn->ipv4_traffic_ok) ||
              (tor_addr_family(&addr) == AF_INET6 && !conn->ipv6_traffic_ok)) {
            log_fn(LOG_PROTOCOL_WARN, LD_APP,
                   "Got an EXITPOLICY failure on a connection with a "
                   "mismatched family. Closing.");
            connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
            return 0;
          }
          if (get_options()->ClientDNSRejectInternalAddresses &&
              tor_addr_is_internal(&addr, 0)) {
            log_info(LD_APP,"Address '%s' resolved to internal. Closing,",
                     safe_str(conn->socks_request->address));
            connection_mark_unattached_ap(conn, END_STREAM_REASON_TORPROTOCOL);
            return 0;
          }

          client_dns_set_addressmap(conn,
                                    conn->socks_request->address, &addr,
                                    conn->chosen_exit_name, ttl);

          {
            char new_addr[TOR_ADDR_BUF_LEN];
            tor_addr_to_str(new_addr, &addr, sizeof(new_addr), 1);
            if (strcmp(conn->socks_request->address, new_addr)) {
              strlcpy(conn->socks_request->address, new_addr,
                      sizeof(conn->socks_request->address));
              control_event_stream_status(conn, STREAM_EVENT_REMAP, 0);
            }
          }
        }
        /* check if he *ought* to have allowed it */

        adjust_exit_policy_from_exitpolicy_failure(circ,
                                                   conn,
                                                   exitrouter,
                                                   &addr);

        if (conn->chosen_exit_optional ||
            conn->chosen_exit_retries) {
          /* stop wanting a specific exit */
          conn->chosen_exit_optional = 0;
          /* A non-zero chosen_exit_retries can happen if we set a
           * TrackHostExits for this address under a port that the exit
           * relay allows, but then try the same address with a different
           * port that it doesn't allow to exit. We shouldn't unregister
           * the mapping, since it is probably still wanted on the
           * original port. But now we give away to the exit relay that
           * we probably have a TrackHostExits on it. So be it. */
          conn->chosen_exit_retries = 0;
          tor_free(conn->chosen_exit_name); /* clears it */
        }
        if (connection_ap_detach_retriable(conn, circ, control_reason) >= 0)
          return 0;
        /* else, conn will get closed below */
        break;
      }
      case END_STREAM_REASON_CONNECTREFUSED:
        if (!conn->chosen_exit_optional)
          break; /* break means it'll close, below */
        /* Else fall through: expire this circuit, clear the
         * chosen_exit_name field, and try again. */
      case END_STREAM_REASON_RESOLVEFAILED:
      case END_STREAM_REASON_TIMEOUT:
      case END_STREAM_REASON_MISC:
      case END_STREAM_REASON_NOROUTE:
        if (client_dns_incr_failures(conn->socks_request->address)
            < MAX_RESOLVE_FAILURES) {
          /* We haven't retried too many times; reattach the connection. */
          circuit_log_path(LOG_INFO,LD_APP,circ);
          /* Mark this circuit "unusable for new streams". */
          mark_circuit_unusable_for_new_conns(circ);

          if (conn->chosen_exit_optional) {
            /* stop wanting a specific exit */
            conn->chosen_exit_optional = 0;
            tor_free(conn->chosen_exit_name); /* clears it */
          }
          if (connection_ap_detach_retriable(conn, circ, control_reason) >= 0)
            return 0;
          /* else, conn will get closed below */
        } else {
          log_notice(LD_APP,
                     "Have tried resolving or connecting to address '%s' "
                     "at %d different places. Giving up.",
                     safe_str(conn->socks_request->address),
                     MAX_RESOLVE_FAILURES);
          /* clear the failures, so it will have a full try next time */
          client_dns_clear_failures(conn->socks_request->address);
        }
        break;
      case END_STREAM_REASON_HIBERNATING:
      case END_STREAM_REASON_RESOURCELIMIT:
        if (exitrouter) {
          policies_set_node_exitpolicy_to_reject_all(exitrouter);
        }
        if (conn->chosen_exit_optional) {
          /* stop wanting a specific exit */
          conn->chosen_exit_optional = 0;
          tor_free(conn->chosen_exit_name); /* clears it */
        }
        if (connection_ap_detach_retriable(conn, circ, control_reason) >= 0)
          return 0;
        /* else, will close below */
        break;
    } /* end switch */
    log_info(LD_APP,"Giving up on retrying; conn can't be handled.");
  }

  log_info(LD_APP,
           "Edge got end (%s) before we're connected. Marking for close.",
       stream_end_reason_to_string(rh->length > 0 ? reason : -1));
  circuit_log_path(LOG_INFO,LD_APP,circ);
  /* need to test because of detach_retriable */
  if (!ENTRY_TO_CONN(conn)->marked_for_close)
    connection_mark_unattached_ap(conn, control_reason);
  return 0;
}

/** Called when we have gotten an END_REASON_EXITPOLICY failure on <b>circ</b>
 * for <b>conn</b>, while attempting to connect via <b>node</b>.  If the node
 * told us which address it rejected, then <b>addr</b> is that address;
 * otherwise it is AF_UNSPEC.
 *
 * If we are sure the node should have allowed this address, mark the node as
 * having a reject *:* exit policy.  Otherwise, mark the circuit as unusable
 * for this particular address.
 **/
static void
adjust_exit_policy_from_exitpolicy_failure(origin_circuit_t *circ,
                                           entry_connection_t *conn,
                                           node_t *node,
                                           const tor_addr_t *addr)
{
  int make_reject_all = 0;
  const sa_family_t family = tor_addr_family(addr);

  if (node) {
    tor_addr_t tmp;
    int asked_for_family = tor_addr_parse(&tmp, conn->socks_request->address);
    if (family == AF_UNSPEC) {
      make_reject_all = 1;
    } else if (node_exit_policy_is_exact(node, family) &&
               asked_for_family != -1 && !conn->chosen_exit_name) {
      make_reject_all = 1;
    }

    if (make_reject_all) {
      log_info(LD_APP,
               "Exitrouter %s seems to be more restrictive than its exit "
               "policy. Not using this router as exit for now.",
               node_describe(node));
      policies_set_node_exitpolicy_to_reject_all(node);
    }
  }

  if (family != AF_UNSPEC)
    addr_policy_append_reject_addr(&circ->prepend_policy, addr);
}

/** Helper: change the socks_request-&gt;address field on conn to the
 * dotted-quad representation of <b>new_addr</b>,
 * and send an appropriate REMAP event. */
static void
remap_event_helper(entry_connection_t *conn, const tor_addr_t *new_addr)
{
  tor_addr_to_str(conn->socks_request->address, new_addr,
                  sizeof(conn->socks_request->address),
                  1);
  control_event_stream_status(conn, STREAM_EVENT_REMAP,
                              REMAP_STREAM_SOURCE_EXIT);
}

/** Extract the contents of a connected cell in <b>cell</b>, whose relay
 * header has already been parsed into <b>rh</b>. On success, set
 * <b>addr_out</b> to the address we're connected to, and <b>ttl_out</b> to
 * the ttl of that address, in seconds, and return 0.  On failure, return
 * -1. */
STATIC int
connected_cell_parse(const relay_header_t *rh, const cell_t *cell,
                     tor_addr_t *addr_out, int *ttl_out)
{
  uint32_t bytes;
  const uint8_t *payload = cell->payload + RELAY_HEADER_SIZE;

  tor_addr_make_unspec(addr_out);
  *ttl_out = -1;
  if (rh->length == 0)
    return 0;
  if (rh->length < 4)
    return -1;
  bytes = ntohl(get_uint32(payload));

  /* If bytes is 0, this is maybe a v6 address. Otherwise it's a v4 address */
  if (bytes != 0) {
    /* v4 address */
    tor_addr_from_ipv4h(addr_out, bytes);
    if (rh->length >= 8) {
      bytes = ntohl(get_uint32(payload + 4));
      if (bytes <= INT32_MAX)
        *ttl_out = bytes;
    }
  } else {
    if (rh->length < 25) /* 4 bytes of 0s, 1 addr, 16 ipv4, 4 ttl. */
      return -1;
    if (get_uint8(payload + 4) != 6)
      return -1;
    tor_addr_from_ipv6_bytes(addr_out, (char*)(payload + 5));
    bytes = ntohl(get_uint32(payload + 21));
    if (bytes <= INT32_MAX)
      *ttl_out = (int) bytes;
  }
  return 0;
}

/** An incoming relay cell has arrived from circuit <b>circ</b> to
 * stream <b>conn</b>.
 *
 * The arguments here are the same as in
 * connection_edge_process_relay_cell() below; this function is called
 * from there when <b>conn</b> is defined and not in an open state.
 */
static int
connection_edge_process_relay_cell_not_open(
    relay_header_t *rh, cell_t *cell, circuit_t *circ,
    edge_connection_t *conn, crypt_path_t *layer_hint)
{
  if (rh->command == RELAY_COMMAND_END) {
    if (CIRCUIT_IS_ORIGIN(circ) && conn->base_.type == CONN_TYPE_AP) {
      return connection_ap_process_end_not_open(rh, cell,
                                                TO_ORIGIN_CIRCUIT(circ),
                                                EDGE_TO_ENTRY_CONN(conn),
                                                layer_hint);
    } else {
      /* we just got an 'end', don't need to send one */
      conn->edge_has_sent_end = 1;
      conn->end_reason = *(cell->payload+RELAY_HEADER_SIZE) |
                         END_STREAM_REASON_FLAG_REMOTE;
      connection_mark_for_close(TO_CONN(conn));
      return 0;
    }
  }

  if (conn->base_.type == CONN_TYPE_AP &&
      rh->command == RELAY_COMMAND_CONNECTED) {
    tor_addr_t addr;
    int ttl;
    entry_connection_t *entry_conn = EDGE_TO_ENTRY_CONN(conn);
    tor_assert(CIRCUIT_IS_ORIGIN(circ));
    if (conn->base_.state != AP_CONN_STATE_CONNECT_WAIT) {
      log_fn(LOG_PROTOCOL_WARN, LD_APP,
             "Got 'connected' while not in state connect_wait. Dropping.");
      return 0;
    }
    conn->base_.state = AP_CONN_STATE_OPEN;
    log_info(LD_APP,"'connected' received after %d seconds.",
             (int)(time(NULL) - conn->base_.timestamp_lastread));
    if (connected_cell_parse(rh, cell, &addr, &ttl) < 0) {
      log_fn(LOG_PROTOCOL_WARN, LD_APP,
             "Got a badly formatted connected cell. Closing.");
      connection_edge_end(conn, END_STREAM_REASON_TORPROTOCOL);
      connection_mark_unattached_ap(entry_conn, END_STREAM_REASON_TORPROTOCOL);
    }
    if (tor_addr_family(&addr) != AF_UNSPEC) {
      const sa_family_t family = tor_addr_family(&addr);
      if (tor_addr_is_null(&addr) ||
          (get_options()->ClientDNSRejectInternalAddresses &&
           tor_addr_is_internal(&addr, 0))) {
        log_info(LD_APP, "...but it claims the IP address was %s. Closing.",
                 fmt_addr(&addr));
        connection_edge_end(conn, END_STREAM_REASON_TORPROTOCOL);
        connection_mark_unattached_ap(entry_conn,
                                      END_STREAM_REASON_TORPROTOCOL);
        return 0;
      }

      if ((family == AF_INET && ! entry_conn->ipv4_traffic_ok) ||
          (family == AF_INET6 && ! entry_conn->ipv6_traffic_ok)) {
        log_fn(LOG_PROTOCOL_WARN, LD_APP,
               "Got a connected cell to %s with unsupported address family."
               " Closing.", fmt_addr(&addr));
        connection_edge_end(conn, END_STREAM_REASON_TORPROTOCOL);
        connection_mark_unattached_ap(entry_conn,
                                      END_STREAM_REASON_TORPROTOCOL);
        return 0;
      }

      client_dns_set_addressmap(entry_conn,
                                entry_conn->socks_request->address, &addr,
                                entry_conn->chosen_exit_name, ttl);

      remap_event_helper(entry_conn, &addr);
    }
    circuit_log_path(LOG_INFO,LD_APP,TO_ORIGIN_CIRCUIT(circ));
    /* don't send a socks reply to transparent conns */
    tor_assert(entry_conn->socks_request != NULL);
    if (!entry_conn->socks_request->has_finished)
      connection_ap_handshake_socks_reply(entry_conn, NULL, 0, 0);

    /* Was it a linked dir conn? If so, a dir request just started to
     * fetch something; this could be a bootstrap status milestone. */
    log_debug(LD_APP, "considering");
    if (TO_CONN(conn)->linked_conn &&
        TO_CONN(conn)->linked_conn->type == CONN_TYPE_DIR) {
      connection_t *dirconn = TO_CONN(conn)->linked_conn;
      log_debug(LD_APP, "it is! %d", dirconn->purpose);
      switch (dirconn->purpose) {
        case DIR_PURPOSE_FETCH_CERTIFICATE:
          if (consensus_is_waiting_for_certs())
            control_event_bootstrap(BOOTSTRAP_STATUS_LOADING_KEYS, 0);
          break;
        case DIR_PURPOSE_FETCH_CONSENSUS:
          control_event_bootstrap(BOOTSTRAP_STATUS_LOADING_STATUS, 0);
          break;
        case DIR_PURPOSE_FETCH_SERVERDESC:
        case DIR_PURPOSE_FETCH_MICRODESC:
          if (TO_DIR_CONN(dirconn)->router_purpose == ROUTER_PURPOSE_GENERAL)
            control_event_bootstrap(BOOTSTRAP_STATUS_LOADING_DESCRIPTORS,
                                    count_loading_descriptors_progress());
          break;
      }
    }
    /* This is definitely a success, so forget about any pending data we
     * had sent. */
    if (entry_conn->pending_optimistic_data) {
      generic_buffer_free(entry_conn->pending_optimistic_data);
      entry_conn->pending_optimistic_data = NULL;
    }

    /* handle anything that might have queued */
    if (connection_edge_package_raw_inbuf(conn, 1, NULL) < 0) {
      /* (We already sent an end cell if possible) */
      connection_mark_for_close(TO_CONN(conn));
      return 0;
    }
    return 0;
  }
  if (conn->base_.type == CONN_TYPE_AP &&
      rh->command == RELAY_COMMAND_RESOLVED) {
    int ttl;
    int answer_len;
    uint8_t answer_type;
    entry_connection_t *entry_conn = EDGE_TO_ENTRY_CONN(conn);
    if (conn->base_.state != AP_CONN_STATE_RESOLVE_WAIT) {
      log_fn(LOG_PROTOCOL_WARN, LD_APP, "Got a 'resolved' cell while "
             "not in state resolve_wait. Dropping.");
      return 0;
    }
    tor_assert(SOCKS_COMMAND_IS_RESOLVE(entry_conn->socks_request->command));
    answer_len = cell->payload[RELAY_HEADER_SIZE+1];
    if (rh->length < 2 || answer_len+2>rh->length) {
      log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
             "Dropping malformed 'resolved' cell");
      connection_mark_unattached_ap(entry_conn, END_STREAM_REASON_TORPROTOCOL);
      return 0;
    }
    answer_type = cell->payload[RELAY_HEADER_SIZE];
    if (rh->length >= answer_len+6)
      ttl = (int)ntohl(get_uint32(cell->payload+RELAY_HEADER_SIZE+
                                  2+answer_len));
    else
      ttl = -1;
    if (answer_type == RESOLVED_TYPE_IPV4 ||
        answer_type == RESOLVED_TYPE_IPV6) {
      tor_addr_t addr;
      if (decode_address_from_payload(&addr, cell->payload+RELAY_HEADER_SIZE,
                                      rh->length) &&
          tor_addr_is_internal(&addr, 0) &&
          get_options()->ClientDNSRejectInternalAddresses) {
        log_info(LD_APP,"Got a resolve with answer %s. Rejecting.",
                 fmt_addr(&addr));
        connection_ap_handshake_socks_resolved(entry_conn,
                                               RESOLVED_TYPE_ERROR_TRANSIENT,
                                               0, NULL, 0, TIME_MAX);
        connection_mark_unattached_ap(entry_conn,
                                      END_STREAM_REASON_TORPROTOCOL);
        return 0;
      }
    }
    connection_ap_handshake_socks_resolved(entry_conn,
                   answer_type,
                   cell->payload[RELAY_HEADER_SIZE+1], /*answer_len*/
                   cell->payload+RELAY_HEADER_SIZE+2, /*answer*/
                   ttl,
                   -1);
    if (answer_type == RESOLVED_TYPE_IPV4 && answer_len == 4) {
      tor_addr_t addr;
      tor_addr_from_ipv4n(&addr,
                          get_uint32(cell->payload+RELAY_HEADER_SIZE+2));
      remap_event_helper(entry_conn, &addr);
    } else if (answer_type == RESOLVED_TYPE_IPV6 && answer_len == 16) {
      tor_addr_t addr;
      tor_addr_from_ipv6_bytes(&addr,
                               (char*)(cell->payload+RELAY_HEADER_SIZE+2));
      remap_event_helper(entry_conn, &addr);
    }
    connection_mark_unattached_ap(entry_conn,
                              END_STREAM_REASON_DONE |
                              END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED);
    return 0;
  }

  log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
         "Got an unexpected relay command %d, in state %d (%s). Dropping.",
         rh->command, conn->base_.state,
         conn_state_to_string(conn->base_.type, conn->base_.state));
  return 0; /* for forward compatibility, don't kill the circuit */
//  connection_edge_end(conn, END_STREAM_REASON_TORPROTOCOL);
//  connection_mark_for_close(conn);
//  return -1;
}

/** An incoming relay cell has arrived on circuit <b>circ</b>. If
 * <b>conn</b> is NULL this is a control cell, else <b>cell</b> is
 * destined for <b>conn</b>.
 *
 * If <b>layer_hint</b> is defined, then we're the origin of the
 * circuit, and it specifies the hop that packaged <b>cell</b>.
 *
 * Return -reason if you want to warn and tear down the circuit, else 0.
 */
static int
connection_edge_process_relay_cell(cell_t *cell, circuit_t *circ,
                                   edge_connection_t *conn,
                                   crypt_path_t *layer_hint)
{
  static int num_seen=0;
  relay_header_t rh;
  unsigned domain = layer_hint?LD_APP:LD_EXIT;
  int reason;
  int optimistic_data = 0; /* Set to 1 if we receive data on a stream
                            * that's in the EXIT_CONN_STATE_RESOLVING
                            * or EXIT_CONN_STATE_CONNECTING states. */

  tor_assert(cell);
  tor_assert(circ);

  relay_header_unpack(&rh, cell->payload);
//  log_fn(LOG_DEBUG,"command %d stream %d", rh.command, rh.stream_id);
  num_seen++;
  log_debug(domain, "Now seen %d relay cells here (command %d, stream %d).",
            num_seen, rh.command, rh.stream_id);

  if (rh.length > RELAY_PAYLOAD_SIZE) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Relay cell length field too long. Closing circuit.");
    return - END_CIRC_REASON_TORPROTOCOL;
  }

  if (rh.stream_id == 0) {
    switch (rh.command) {
      case RELAY_COMMAND_BEGIN:
      case RELAY_COMMAND_CONNECTED:
      case RELAY_COMMAND_DATA:
      case RELAY_COMMAND_END:
      case RELAY_COMMAND_RESOLVE:
      case RELAY_COMMAND_RESOLVED:
      case RELAY_COMMAND_BEGIN_DIR:
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL, "Relay command %d with zero "
               "stream_id. Dropping.", (int)rh.command);
        return 0;
      default:
        ;
    }
  }

  /* either conn is NULL, in which case we've got a control cell, or else
   * conn points to the recognized stream. */

  if (conn && !connection_state_is_open(TO_CONN(conn))) {
    if (conn->base_.type == CONN_TYPE_EXIT &&
        (conn->base_.state == EXIT_CONN_STATE_CONNECTING ||
         conn->base_.state == EXIT_CONN_STATE_RESOLVING) &&
        rh.command == RELAY_COMMAND_DATA) {
      /* Allow DATA cells to be delivered to an exit node in state
       * EXIT_CONN_STATE_CONNECTING or EXIT_CONN_STATE_RESOLVING.
       * This speeds up HTTP, for example. */
      optimistic_data = 1;
    } else {
      return connection_edge_process_relay_cell_not_open(
               &rh, cell, circ, conn, layer_hint);
    }
  }

  switch (rh.command) {
    case RELAY_COMMAND_DROP:
//      log_info(domain,"Got a relay-level padding cell. Dropping.");
      return 0;
    case RELAY_COMMAND_BEGIN:
    case RELAY_COMMAND_BEGIN_DIR:
      if (layer_hint &&
          circ->purpose != CIRCUIT_PURPOSE_S_REND_JOINED) {
        log_fn(LOG_PROTOCOL_WARN, LD_APP,
               "Relay begin request unsupported at AP. Dropping.");
        return 0;
      }
      if (circ->purpose == CIRCUIT_PURPOSE_S_REND_JOINED &&
          layer_hint != TO_ORIGIN_CIRCUIT(circ)->cpath->prev) {
        log_fn(LOG_PROTOCOL_WARN, LD_APP,
               "Relay begin request to Hidden Service "
               "from intermediary node. Dropping.");
        return 0;
      }
      if (conn) {
        log_fn(LOG_PROTOCOL_WARN, domain,
               "Begin cell for known stream. Dropping.");
        return 0;
      }
      if (rh.command == RELAY_COMMAND_BEGIN_DIR) {
        /* Assign this circuit and its app-ward OR connection a unique ID,
         * so that we can measure download times. The local edge and dir
         * connection will be assigned the same ID when they are created
         * and linked. */
        static uint64_t next_id = 0;
        circ->dirreq_id = ++next_id;
        TO_OR_CIRCUIT(circ)->p_chan->dirreq_id = circ->dirreq_id;
      }

      return connection_exit_begin_conn(cell, circ);
    case RELAY_COMMAND_DATA:
      ++stats_n_data_cells_received;
      if (( layer_hint && --layer_hint->deliver_window < 0) ||
          (!layer_hint && --circ->deliver_window < 0)) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "(relay data) circ deliver_window below 0. Killing.");
        if (conn) {
          /* XXXX Do we actually need to do this?  Will killing the circuit
           * not send an END and mark the stream for close as appropriate? */
          connection_edge_end(conn, END_STREAM_REASON_TORPROTOCOL);
          connection_mark_for_close(TO_CONN(conn));
        }
        return -END_CIRC_REASON_TORPROTOCOL;
      }
      log_debug(domain,"circ deliver_window now %d.", layer_hint ?
                layer_hint->deliver_window : circ->deliver_window);

      circuit_consider_sending_sendme(circ, layer_hint);

      if (!conn) {
        log_info(domain,"data cell dropped, unknown stream (streamid %d).",
                 rh.stream_id);
        return 0;
      }

      if (--conn->deliver_window < 0) { /* is it below 0 after decrement? */
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "(relay data) conn deliver_window below 0. Killing.");
        return -END_CIRC_REASON_TORPROTOCOL;
      }

      stats_n_data_bytes_received += rh.length;
      connection_write_to_buf((char*)(cell->payload + RELAY_HEADER_SIZE),
                              rh.length, TO_CONN(conn));

      if (!optimistic_data) {
        /* Only send a SENDME if we're not getting optimistic data; otherwise
         * a SENDME could arrive before the CONNECTED.
         */
        connection_edge_consider_sending_sendme(conn);
      }

      return 0;
    case RELAY_COMMAND_END:
      reason = rh.length > 0 ?
        get_uint8(cell->payload+RELAY_HEADER_SIZE) : END_STREAM_REASON_MISC;
      if (!conn) {
        log_info(domain,"end cell (%s) dropped, unknown stream.",
                 stream_end_reason_to_string(reason));
        return 0;
      }
/* XXX add to this log_fn the exit node's nickname? */
      log_info(domain,TOR_SOCKET_T_FORMAT": end cell (%s) for stream %d. "
               "Removing stream.",
               conn->base_.s,
               stream_end_reason_to_string(reason),
               conn->stream_id);
      if (conn->base_.type == CONN_TYPE_AP) {
        entry_connection_t *entry_conn = EDGE_TO_ENTRY_CONN(conn);
        if (entry_conn->socks_request &&
            !entry_conn->socks_request->has_finished)
          log_warn(LD_BUG,
                   "open stream hasn't sent socks answer yet? Closing.");
      }
      /* We just *got* an end; no reason to send one. */
      conn->edge_has_sent_end = 1;
      if (!conn->end_reason)
        conn->end_reason = reason | END_STREAM_REASON_FLAG_REMOTE;
      if (!conn->base_.marked_for_close) {
        /* only mark it if not already marked. it's possible to
         * get the 'end' right around when the client hangs up on us. */
        connection_mark_and_flush(TO_CONN(conn));
      }
      return 0;
    case RELAY_COMMAND_EXTEND:
    case RELAY_COMMAND_EXTEND2: {
      static uint64_t total_n_extend=0, total_nonearly=0;
      total_n_extend++;
      if (rh.stream_id) {
        log_fn(LOG_PROTOCOL_WARN, domain,
               "'extend' cell received for non-zero stream. Dropping.");
        return 0;
      }
      if (cell->command != CELL_RELAY_EARLY &&
          !networkstatus_get_param(NULL,"AllowNonearlyExtend",0,0,1)) {
#define EARLY_WARNING_INTERVAL 3600
        static ratelim_t early_warning_limit =
          RATELIM_INIT(EARLY_WARNING_INTERVAL);
        char *m;
        if (cell->command == CELL_RELAY) {
          ++total_nonearly;
          if ((m = rate_limit_log(&early_warning_limit, approx_time()))) {
            double percentage = ((double)total_nonearly)/total_n_extend;
            percentage *= 100;
            log_fn(LOG_PROTOCOL_WARN, domain, "EXTEND cell received, "
                   "but not via RELAY_EARLY. Dropping.%s", m);
            log_fn(LOG_PROTOCOL_WARN, domain, "  (We have dropped %.02f%% of "
                   "all EXTEND cells for this reason)", percentage);
            tor_free(m);
          }
        } else {
          log_fn(LOG_WARN, domain,
                 "EXTEND cell received, in a cell with type %d! Dropping.",
                 cell->command);
        }
        return 0;
      }
      return circuit_extend(cell, circ);
    }
    case RELAY_COMMAND_EXTENDED:
    case RELAY_COMMAND_EXTENDED2:
      if (!layer_hint) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "'extended' unsupported at non-origin. Dropping.");
        return 0;
      }
      log_debug(domain,"Got an extended cell! Yay.");
      {
        extended_cell_t extended_cell;
        if (extended_cell_parse(&extended_cell, rh.command,
                        (const uint8_t*)cell->payload+RELAY_HEADER_SIZE,
                        rh.length)<0) {
          log_warn(LD_PROTOCOL,
                   "Can't parse EXTENDED cell; killing circuit.");
          return -END_CIRC_REASON_TORPROTOCOL;
        }
        if ((reason = circuit_finish_handshake(TO_ORIGIN_CIRCUIT(circ),
                                         &extended_cell.created_cell)) < 0) {
          log_warn(domain,"circuit_finish_handshake failed.");
          return reason;
        }
      }
      if ((reason=circuit_send_next_onion_skin(TO_ORIGIN_CIRCUIT(circ)))<0) {
        log_info(domain,"circuit_send_next_onion_skin() failed.");
        return reason;
      }
      return 0;
    case RELAY_COMMAND_TRUNCATE:
      if (layer_hint) {
        log_fn(LOG_PROTOCOL_WARN, LD_APP,
               "'truncate' unsupported at origin. Dropping.");
        return 0;
      }
      if (circ->n_hop) {
        if (circ->n_chan)
          log_warn(LD_BUG, "n_chan and n_hop set on the same circuit!");
        extend_info_free(circ->n_hop);
        circ->n_hop = NULL;
        tor_free(circ->n_chan_create_cell);
        circuit_set_state(circ, CIRCUIT_STATE_OPEN);
      }
      if (circ->n_chan) {
        uint8_t trunc_reason = get_uint8(cell->payload + RELAY_HEADER_SIZE);
        circuit_clear_cell_queue(circ, circ->n_chan);
        channel_send_destroy(circ->n_circ_id, circ->n_chan,
                             trunc_reason);
        circuit_set_n_circid_chan(circ, 0, NULL);
      }
      log_debug(LD_EXIT, "Processed 'truncate', replying.");
      {
        char payload[1];
        payload[0] = (char)END_CIRC_REASON_REQUESTED;
        relay_send_command_from_edge(0, circ, RELAY_COMMAND_TRUNCATED,
                                     payload, sizeof(payload), NULL);
      }
      return 0;
    case RELAY_COMMAND_TRUNCATED:
      if (!layer_hint) {
        log_fn(LOG_PROTOCOL_WARN, LD_EXIT,
               "'truncated' unsupported at non-origin. Dropping.");
        return 0;
      }
      circuit_truncated(TO_ORIGIN_CIRCUIT(circ), layer_hint,
                        get_uint8(cell->payload + RELAY_HEADER_SIZE));
      return 0;
    case RELAY_COMMAND_CONNECTED:
      if (conn) {
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "'connected' unsupported while open. Closing circ.");
        return -END_CIRC_REASON_TORPROTOCOL;
      }
      log_info(domain,
               "'connected' received, no conn attached anymore. Ignoring.");
      return 0;
    case RELAY_COMMAND_SENDME:
      if (!rh.stream_id) {
        if (layer_hint) {
          if (layer_hint->package_window + CIRCWINDOW_INCREMENT >
                CIRCWINDOW_START_MAX) {
            static struct ratelim_t exit_warn_ratelim = RATELIM_INIT(600);
            log_fn_ratelim(&exit_warn_ratelim, LOG_WARN, LD_PROTOCOL,
                   "Unexpected sendme cell from exit relay. "
                   "Closing circ.");
            return -END_CIRC_REASON_TORPROTOCOL;
          }
          layer_hint->package_window += CIRCWINDOW_INCREMENT;
          log_debug(LD_APP,"circ-level sendme at origin, packagewindow %d.",
                    layer_hint->package_window);
          circuit_resume_edge_reading(circ, layer_hint);
        } else {
          if (circ->package_window + CIRCWINDOW_INCREMENT >
                CIRCWINDOW_START_MAX) {
            static struct ratelim_t client_warn_ratelim = RATELIM_INIT(600);
            log_fn_ratelim(&client_warn_ratelim, LOG_WARN, LD_PROTOCOL,
                   "Unexpected sendme cell from client. "
                   "Closing circ (window %d).",
                   circ->package_window);
            return -END_CIRC_REASON_TORPROTOCOL;
          }
          circ->package_window += CIRCWINDOW_INCREMENT;
          log_debug(LD_APP,
                    "circ-level sendme at non-origin, packagewindow %d.",
                    circ->package_window);
          circuit_resume_edge_reading(circ, layer_hint);
        }
        return 0;
      }
      if (!conn) {
        log_info(domain,"sendme cell dropped, unknown stream (streamid %d).",
                 rh.stream_id);
        return 0;
      }
      conn->package_window += STREAMWINDOW_INCREMENT;
      log_debug(domain,"stream-level sendme, packagewindow now %d.",
                conn->package_window);
      if (circuit_queue_streams_are_blocked(circ)) {
        /* Still waiting for queue to flush; don't touch conn */
        return 0;
      }
      connection_start_reading(TO_CONN(conn));
      /* handle whatever might still be on the inbuf */
      if (connection_edge_package_raw_inbuf(conn, 1, NULL) < 0) {
        /* (We already sent an end cell if possible) */
        connection_mark_for_close(TO_CONN(conn));
        return 0;
      }
      return 0;
    case RELAY_COMMAND_RESOLVE:
      if (layer_hint) {
        log_fn(LOG_PROTOCOL_WARN, LD_APP,
               "resolve request unsupported at AP; dropping.");
        return 0;
      } else if (conn) {
        log_fn(LOG_PROTOCOL_WARN, domain,
               "resolve request for known stream; dropping.");
        return 0;
      } else if (circ->purpose != CIRCUIT_PURPOSE_OR) {
        log_fn(LOG_PROTOCOL_WARN, domain,
               "resolve request on circ with purpose %d; dropping",
               circ->purpose);
        return 0;
      }
      connection_exit_begin_resolve(cell, TO_OR_CIRCUIT(circ));
      return 0;
    case RELAY_COMMAND_RESOLVED:
      if (conn) {
        log_fn(LOG_PROTOCOL_WARN, domain,
               "'resolved' unsupported while open. Closing circ.");
        return -END_CIRC_REASON_TORPROTOCOL;
      }
      log_info(domain,
               "'resolved' received, no conn attached anymore. Ignoring.");
      return 0;
    case RELAY_COMMAND_ESTABLISH_INTRO:
    case RELAY_COMMAND_ESTABLISH_RENDEZVOUS:
    case RELAY_COMMAND_INTRODUCE1:
    case RELAY_COMMAND_INTRODUCE2:
    case RELAY_COMMAND_INTRODUCE_ACK:
    case RELAY_COMMAND_RENDEZVOUS1:
    case RELAY_COMMAND_RENDEZVOUS2:
    case RELAY_COMMAND_INTRO_ESTABLISHED:
    case RELAY_COMMAND_RENDEZVOUS_ESTABLISHED:
      rend_process_relay_cell(circ, layer_hint,
                              rh.command, rh.length,
                              cell->payload+RELAY_HEADER_SIZE);
      return 0;
  }
  log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
         "Received unknown relay command %d. Perhaps the other side is using "
         "a newer version of Tor? Dropping.",
         rh.command);
  return 0; /* for forward compatibility, don't kill the circuit */
}

/** How many relay_data cells have we built, ever? */
uint64_t stats_n_data_cells_packaged = 0;
/** How many bytes of data have we put in relay_data cells have we built,
 * ever? This would be RELAY_PAYLOAD_SIZE*stats_n_data_cells_packaged if
 * every relay cell we ever sent were completely full of data. */
uint64_t stats_n_data_bytes_packaged = 0;
/** How many relay_data cells have we received, ever? */
uint64_t stats_n_data_cells_received = 0;
/** How many bytes of data have we received relay_data cells, ever? This would
 * be RELAY_PAYLOAD_SIZE*stats_n_data_cells_packaged if every relay cell we
 * ever received were completely full of data. */
uint64_t stats_n_data_bytes_received = 0;

/** If <b>conn</b> has an entire relay payload of bytes on its inbuf (or
 * <b>package_partial</b> is true), and the appropriate package windows aren't
 * empty, grab a cell and send it down the circuit.
 *
 * If *<b>max_cells</b> is given, package no more than max_cells.  Decrement
 * *<b>max_cells</b> by the number of cells packaged.
 *
 * Return -1 (and send a RELAY_COMMAND_END cell if necessary) if conn should
 * be marked for close, else return 0.
 */
int
connection_edge_package_raw_inbuf(edge_connection_t *conn, int package_partial,
                                  int *max_cells)
{
  size_t bytes_to_process, length;
  char payload[CELL_PAYLOAD_SIZE];
  circuit_t *circ;
  const unsigned domain = conn->base_.type == CONN_TYPE_AP ? LD_APP : LD_EXIT;
  int sending_from_optimistic = 0;
  entry_connection_t *entry_conn =
    conn->base_.type == CONN_TYPE_AP ? EDGE_TO_ENTRY_CONN(conn) : NULL;
  const int sending_optimistically =
    entry_conn &&
    conn->base_.type == CONN_TYPE_AP &&
    conn->base_.state != AP_CONN_STATE_OPEN;
  crypt_path_t *cpath_layer = conn->cpath_layer;

  tor_assert(conn);

  if (conn->base_.marked_for_close) {
    log_warn(LD_BUG,
             "called on conn that's already marked for close at %s:%d.",
             conn->base_.marked_for_close_file, conn->base_.marked_for_close);
    return 0;
  }

  if (max_cells && *max_cells <= 0)
    return 0;

 repeat_connection_edge_package_raw_inbuf:

  circ = circuit_get_by_edge_conn(conn);
  if (!circ) {
    log_info(domain,"conn has no circuit! Closing.");
    conn->end_reason = END_STREAM_REASON_CANT_ATTACH;
    return -1;
  }

  if (circuit_consider_stop_edge_reading(circ, cpath_layer))
    return 0;

  if (conn->package_window <= 0) {
    log_info(domain,"called with package_window %d. Skipping.",
             conn->package_window);
    connection_stop_reading(TO_CONN(conn));
    return 0;
  }

  sending_from_optimistic = entry_conn &&
    entry_conn->sending_optimistic_data != NULL;

  if (PREDICT_UNLIKELY(sending_from_optimistic)) {
    bytes_to_process = generic_buffer_len(entry_conn->sending_optimistic_data);
    if (PREDICT_UNLIKELY(!bytes_to_process)) {
      log_warn(LD_BUG, "sending_optimistic_data was non-NULL but empty");
      bytes_to_process = connection_get_inbuf_len(TO_CONN(conn));
      sending_from_optimistic = 0;
    }
  } else {
    bytes_to_process = connection_get_inbuf_len(TO_CONN(conn));
  }

  if (!bytes_to_process)
    return 0;

  if (!package_partial && bytes_to_process < RELAY_PAYLOAD_SIZE)
    return 0;

  if (bytes_to_process > RELAY_PAYLOAD_SIZE) {
    length = RELAY_PAYLOAD_SIZE;
  } else {
    length = bytes_to_process;
  }
  stats_n_data_bytes_packaged += length;
  stats_n_data_cells_packaged += 1;

  if (PREDICT_UNLIKELY(sending_from_optimistic)) {
    /* XXXX We could be more efficient here by sometimes packing
     * previously-sent optimistic data in the same cell with data
     * from the inbuf. */
    generic_buffer_get(entry_conn->sending_optimistic_data, payload, length);
    if (!generic_buffer_len(entry_conn->sending_optimistic_data)) {
        generic_buffer_free(entry_conn->sending_optimistic_data);
        entry_conn->sending_optimistic_data = NULL;
    }
  } else {
    connection_fetch_from_buf(payload, length, TO_CONN(conn));
  }

  log_debug(domain,TOR_SOCKET_T_FORMAT": Packaging %d bytes (%d waiting).",
            conn->base_.s,
            (int)length, (int)connection_get_inbuf_len(TO_CONN(conn)));

  if (sending_optimistically && !sending_from_optimistic) {
    /* This is new optimistic data; remember it in case we need to detach and
       retry */
    if (!entry_conn->pending_optimistic_data)
      entry_conn->pending_optimistic_data = generic_buffer_new();
    generic_buffer_add(entry_conn->pending_optimistic_data, payload, length);
  }

  if (connection_edge_send_command(conn, RELAY_COMMAND_DATA,
                                   payload, length) < 0 )
    /* circuit got marked for close, don't continue, don't need to mark conn */
    return 0;

  if (!cpath_layer) { /* non-rendezvous exit */
    tor_assert(circ->package_window > 0);
    circ->package_window--;
  } else { /* we're an AP, or an exit on a rendezvous circ */
    tor_assert(cpath_layer->package_window > 0);
    cpath_layer->package_window--;
  }

  if (--conn->package_window <= 0) { /* is it 0 after decrement? */
    connection_stop_reading(TO_CONN(conn));
    log_debug(domain,"conn->package_window reached 0.");
    circuit_consider_stop_edge_reading(circ, cpath_layer);
    return 0; /* don't process the inbuf any more */
  }
  log_debug(domain,"conn->package_window is now %d",conn->package_window);

  if (max_cells) {
    *max_cells -= 1;
    if (*max_cells <= 0)
      return 0;
  }

  /* handle more if there's more, or return 0 if there isn't */
  goto repeat_connection_edge_package_raw_inbuf;
}

/** Called when we've just received a relay data cell, when
 * we've just finished flushing all bytes to stream <b>conn</b>,
 * or when we've flushed *some* bytes to the stream <b>conn</b>.
 *
 * If conn->outbuf is not too full, and our deliver window is
 * low, send back a suitable number of stream-level sendme cells.
 */
void
connection_edge_consider_sending_sendme(edge_connection_t *conn)
{
  circuit_t *circ;

  if (connection_outbuf_too_full(TO_CONN(conn)))
    return;

  circ = circuit_get_by_edge_conn(conn);
  if (!circ) {
    /* this can legitimately happen if the destroy has already
     * arrived and torn down the circuit */
    log_info(LD_APP,"No circuit associated with conn. Skipping.");
    return;
  }

  while (conn->deliver_window <= STREAMWINDOW_START - STREAMWINDOW_INCREMENT) {
    log_debu