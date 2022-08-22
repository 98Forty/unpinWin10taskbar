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
                                   circ->c