/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "buffers.h"
#include "circuitbuild.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "control.h"
#include "directory.h"
#include "dirserv.h"
#include "dirvote.h"
#include "entrynodes.h"
#include "geoip.h"
#include "onion_main.h"
#include "microdesc.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "policies.h"
#include "rendclient.h"
#include "rendcommon.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"
#include "routerparse.h"
#include "routerset.h"

#if defined(EXPORTMALLINFO) && defined(HAVE_MALLOC_H) && defined(HAVE_MALLINFO)
#ifndef OPENBSD
#include <malloc.h>
#endif
#endif

/**
 * \file directory.c
 * \brief Code to send and fetch directories and router
 * descriptors via HTTP.  Directories use dirserv.c to generate the
 * results; clients use routers.c to parse them.
 **/

/* In-points to directory.c:
 *
 * - directory_post_to_dirservers(), called from
 *   router_upload_dir_desc_to_dirservers() in router.c
 *   upload_service_descriptor() in rendservice.c
 * - directory_get_from_dirserver(), called from
 *   rend_client_refetch_renddesc() in rendclient.c
 *   run_scheduled_events() in onion_main.c
 *   do_hup() in onion_main.c
 * - connection_dir_process_inbuf(), called from
 *   connection_process_inbuf() in connection.c
 * - connection_dir_finished_flushing(), called from
 *   connection_finished_flushing() in connection.c
 * - connection_dir_finished_connecting(), called from
 *   connection_finished_connecting() in connection.c
 */
static void directory_send_command(dir_connection_t *conn,
                             int purpose, int direct, const char *resource,
                             const char *payload, size_t payload_len,
                             time_t if_modified_since);
static int directory_handle_command(dir_connection_t *conn);
static int body_is_plausible(const char *body, size_t body_len, int purpose);
static int purpose_needs_anonymity(uint8_t dir_purpose,
                                   uint8_t router_purpose);
static char *http_get_header(const char *headers, const char *which);
static void http_set_address_origin(const char *headers, connection_t *conn);
static void connection_dir_download_routerdesc_failed(dir_connection_t *conn);
static void connection_dir_bridge_routerdesc_failed(dir_connection_t *conn);
static void connection_dir_download_cert_failed(
                               dir_connection_t *conn, int status_code);
static void connection_dir_retry_bridges(smartlist_t *descs);
static void dir_routerdesc_download_failed(smartlist_t *failed,
                                           int status_code,
                                           int router_purpose,
                                           int was_extrainfo,
                                           int was_descriptor_digests);
static void dir_microdesc_download_failed(smartlist_t *failed,
                                          int status_code);
static void note_client_request(int purpose, int compressed, size_t bytes);
static int client_likes_consensus(networkstatus_t *v, const char *want_url);

static void directory_initiate_command_rend(const char *address,
                                            const tor_addr_t *addr,
                                            uint16_t or_port,
                                            uint16_t dir_port,
                                            const char *digest,
                                            uint8_t dir_purpose,
                                            uint8_t router_purpose,
                                            dir_indirection_t indirection,
                                            const char *resource,
                                            const char *payload,
                                            size_t payload_len,
                                            time_t if_modified_since,
                                            const rend_data_t *rend_query);

/********* START VARIABLES **********/

/** How far in the future do we allow a directory server to tell us it is
 * before deciding that one of us has the wrong time? */
#define ALLOW_DIRECTORY_TIME_SKEW (30*60)

#define X_ADDRESS_HEADER "X-Your-Address-Is: "

/** HTTP cache control: how long do we tell proxies they can cache each
 * kind of document we serve? */
#define FULL_DIR_CACHE_LIFETIME (60*60)
#define RUNNINGROUTERS_CACHE_LIFETIME (20*60)
#define DIRPORTFRONTPAGE_CACHE_LIFETIME (20*60)
#define NETWORKSTATUS_CACHE_LIFETIME (5*60)
#define ROUTERDESC_CACHE_LIFETIME (30*60)
#define ROUTERDESC_BY_DIGEST_CACHE_LIFETIME (48*60*60)
#define ROBOTS_CACHE_LIFETIME (24*60*60)
#define MICRODESC_CACHE_LIFETIME (48*60*60)

/********* END VARIABLES ************/

/** Return true iff the directory purpose <b>dir_purpose</b> (and if it's
 * fetching descriptors, it's fetching them for <b>router_purpose</b>)
 * must use an anonymous connection to a directory. */
static int
purpose_needs_anonymity(uint8_t dir_purpose, uint8_t router_purpose)
{
  if (get_options()->AllDirActionsPrivate)
    return 1;
  if (router_purpose == ROUTER_PURPOSE_BRIDGE)
    return 1; /* if no circuits yet, this might break bootstrapping, but it's
               * needed to be safe. */
  if (dir_purpose == DIR_PURPOSE_UPLOAD_DIR ||
      dir_purpose == DIR_PURPOSE_UPLOAD_VOTE ||
      dir_purpose == DIR_PURPOSE_UPLOAD_SIGNATURES ||
      dir_purpose == DIR_PURPOSE_FETCH_STATUS_VOTE ||
      dir_purpose == DIR_PURPOSE_FETCH_DETACHED_SIGNATURES ||
      dir_purpose == DIR_PURPOSE_FETCH_CONSENSUS ||
      dir_purpose == DIR_PURPOSE_FETCH_CERTIFICATE ||
      dir_purpose == DIR_PURPOSE_FETCH_SERVERDESC ||
      dir_purpose == DIR_PURPOSE_FETCH_EXTRAINFO ||
      dir_purpose == DIR_PURPOSE_FETCH_MICRODESC)
    return 0;
  return 1;
}

/** Return a newly allocated string describing <b>auth</b>. Only describes
 * authority features. */
static char *
authdir_type_to_string(dirinfo_type_t auth)
{
  char *result;
  smartlist_t *lst = smartlist_new();
  if (auth & V1_DIRINFO)
    smartlist_add(lst, (void*)"V1");
  if (auth & V3_DIRINFO)
    smartlist_add(lst, (void*)"V3");
  if (auth & BRIDGE_DIRINFO)
    smartlist_add(lst, (void*)"Bridge");
  if (auth & HIDSERV_DIRINFO)
    smartlist_add(lst, (void*)"Hidden service");
  if (smartlist_len(lst)) {
    result = smartlist_join_strings(lst, ", ", 0, NULL);
  } else {
    result = tor_strdup("[Not an authority]");
  }
  smartlist_free(lst);
  return result;
}

/** Return a string describing a given directory connection purpose. */
static const char *
dir_conn_purpose_to_string(int purpose)
{
  switch (purpose)
    {
    case DIR_PURPOSE_FETCH_RENDDESC:
      return "hidden-service descriptor fetch";
    case DIR_PURPOSE_UPLOAD_DIR:
      return "server descriptor upload";
    case DIR_PURPOSE_UPLOAD_RENDDESC:
      return "hidden-service descriptor upload";
    case DIR_PURPOSE_UPLOAD_VOTE:
      return "server vote upload";
    case DIR_PURPOSE_UPLOAD_SIGNATURES:
      return "consensus signature upload";
    case DIR_PURPOSE_FETCH_SERVERDESC:
      return "server descriptor fetch";
    case DIR_PURPOSE_FETCH_EXTRAINFO:
      return "extra-info fetch";
    case DIR_PURPOSE_FETCH_CONSENSUS:
      return "consensus network-status fetch";
    case DIR_PURPOSE_FETCH_CERTIFICATE:
      return "authority cert fetch";
    case DIR_PURPOSE_FETCH_STATUS_VOTE:
      return "status vote fetch";
    case DIR_PURPOSE_FETCH_DETACHED_SIGNATURES:
      return "consensus signature fetch";
    case DIR_PURPOSE_FETCH_RENDDESC_V2:
      return "hidden-service v2 descriptor fetch";
    case DIR_PURPOSE_UPLOAD_RENDDESC_V2:
      return "hidden-service v2 descriptor upload";
    case DIR_PURPOSE_FETCH_MICRODES