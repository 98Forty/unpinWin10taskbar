/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file networkstatus.h
 * \brief Header file for networkstatus.c.
 **/

#ifndef TOR_NETWORKSTATUS_H
#define TOR_NETWORKSTATUS_H

void networkstatus_reset_warnings(void);
void networkstatus_reset_download_failures(void);
int router_reload_consensus_networkstatus(void);
void routerstatus_free(routerstatus_t *rs);
void networkstatus_vote_free(networkstatus_t *ns);
networkstatus_voter_info_t *networkstatus_get_voter_by_id(
                                       networkstatus_t *vote,
                                       const char *identity);
int networkstatus_check_consensus_signature(networkstatus_t *consensus,
                                            int warn);
int networkstatus_check_document_signature(const networkstatus_t *consensus,
                                           document_signature_t *sig,
                                           const authority_cert_t *cert);
char *networkstatus_get_cache_filename(const char *identity_digest);
int compare_digest_to_routerstatus_entry(const void *_key,
                                         const void **_member);
int compare_digest_to_vote_routerstatus_entry(const void *_key,
                                              const void **_member);
const routerstatus_t *networkstatus_vote_find_entry(networkstatus_t *ns,
                                           