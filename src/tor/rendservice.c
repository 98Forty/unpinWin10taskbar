/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rendservice.c
 * \brief The hidden-service side of rendezvous functionality.
 **/

#define RENDSERVICE_PRIVATE

#include "or.h"
#include "circpathbias.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "config.h"
#include "directory.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "rendclient.h"
#include "rendcommon.h"
#include "rendservice.h"
#include "router.h"
#include "relay.h"
#include "rephist.h"
#include "replaycache.h"
#include "routerlist.h"
#include "routerparse.h"
#include "routerset.h"
#include "xdecoin.h"

static origin_circuit_t *find_intro_circuit(rend_intro_point_t *intro,
                                            const char *pk_digest);
static rend_intro_point_t *find_intro_point(origin_circuit_t *circ);

static extend_info_t *find_rp_for_intro(
    const rend_intro_cell_t *intro,
    uint8_t *need_free_out, char **err_msg_out);

static int intro_point_accepted_intro_count(rend_intro_point_t *intro);
static int intro_point_should_expire_now(rend_intro_point_t *intro,
                                         time_t now);
struct rend_service_t;
static int rend_service_load_keys(struct rend_service_t *s);
static int rend_service_load_auth_keys(struct rend_service_t *s,
                                       const char *hfname);

static ssize_t rend_service_parse_intro_for_v0_or_v1(
    rend_intro_cell_t *intro,
    const uint8_t *buf,
    size_t plaintext_len,
    char **err_msg_out);
static ssize_t rend_service_parse_intro_for_v2(
    rend_intro_cell_t *intro,
    const uint8_t *buf,
    size_t plaintext_len,
    char **err_msg_out);
static ssize_t rend_service_parse_intro_for_v3(
    rend_intro_cell_t *intro,
    const uint8_t *buf,
    size_t plaintext_len,
    char **err_msg_out);

/** Represents the mapping from a virtual port of a rendezvous service to
 * a real port on some IP.
 */
typedef struc