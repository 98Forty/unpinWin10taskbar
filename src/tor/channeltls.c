
/* * Copyright (c) 2012-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channeltls.c
 * \brief channel_t concrete subclass using or_connection_t
 **/

/*
 * Define this so channel.h gives us things only channel_t subclasses
 * should touch.
 */

#define TOR_CHANNEL_INTERNAL_

#include "or.h"
#include "channel.h"
#include "channeltls.h"
#include "circuitmux.h"
#include "circuitmux_ewma.h"
#include "config.h"
#include "connection.h"
#include "connection_or.h"
#include "control.h"
#include "relay.h"
#include "router.h"
#include "routerlist.h"

/** How many CELL_PADDING cells have we received, ever? */
uint64_t stats_n_padding_cells_processed = 0;
/** How many CELL_VERSIONS cells have we received, ever? */
uint64_t stats_n_versions_cells_processed = 0;
/** How many CELL_NETINFO cells have we received, ever? */
uint64_t stats_n_netinfo_cells_processed = 0;
/** How many CELL_VPADDING cells have we received, ever? */
uint64_t stats_n_vpadding_cells_processed = 0;
/** How many CELL_CERTS cells have we received, ever? */
uint64_t stats_n_certs_cells_processed = 0;
/** How many CELL_AUTH_CHALLENGE cells have we received, ever? */
uint64_t stats_n_auth_challenge_cells_processed = 0;
/** How many CELL_AUTHENTICATE cells have we received, ever? */
uint64_t stats_n_authenticate_cells_processed = 0;
/** How many CELL_AUTHORIZE cells have we received, ever? */
uint64_t stats_n_authorize_cells_processed = 0;

/** Active listener, if any */
channel_listener_t *channel_tls_listener = NULL;

/* Utility function declarations */
static void channel_tls_common_init(channel_tls_t *tlschan);

/* channel_tls_t method declarations */

static void channel_tls_close_method(channel_t *chan);
static const char * channel_tls_describe_transport_method(channel_t *chan);
static void channel_tls_free_method(channel_t *chan);
static int
channel_tls_get_remote_addr_method(channel_t *chan, tor_addr_t *addr_out);
static int
channel_tls_get_transport_name_method(channel_t *chan, char **transport_out);
static const char *
channel_tls_get_remote_descr_method(channel_t *chan, int flags);
static int channel_tls_has_queued_writes_method(channel_t *chan);
static int channel_tls_is_canonical_method(channel_t *chan, int req);
static int
channel_tls_matches_extend_info_method(channel_t *chan,
                                       extend_info_t *extend_info);
static int channel_tls_matches_target_method(channel_t *chan,
                                             const tor_addr_t *target);
static int channel_tls_write_cell_method(channel_t *chan,
                                         cell_t *cell);
static int channel_tls_write_packed_cell_method(channel_t *chan,
                                                packed_cell_t *packed_cell);
static int channel_tls_write_var_cell_method(channel_t *chan,
                                             var_cell_t *var_cell);

/* channel_listener_tls_t method declarations */

static void channel_tls_listener_close_method(channel_listener_t *chan_l);
static const char *
channel_tls_listener_describe_transport_method(channel_listener_t *chan_l);

/** Handle incoming cells for the handshake stuff here rather than
 * passing them on up. */

static void channel_tls_process_versions_cell(var_cell_t *cell,
                                              channel_tls_t *tlschan);
static void channel_tls_process_netinfo_cell(cell_t *cell,
                                             channel_tls_t *tlschan);
static void channel_tls_process_certs_cell(var_cell_t *cell,
                                           channel_tls_t *tlschan);
static void channel_tls_process_auth_challenge_cell(var_cell_t *cell,
                                                    channel_tls_t *tlschan);
static void channel_tls_process_authenticate_cell(var_cell_t *cell,
                                                  channel_tls_t *tlschan);
static int command_allowed_before_handshake(uint8_t command);
static int enter_v3_handshake_with_cell(var_cell_t *cell,