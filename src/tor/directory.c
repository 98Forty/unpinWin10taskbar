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
    case DIR_PURPOSE_FETCH_MICRODESC:
      return "microdescriptor fetch";
    }

  log_warn(LD_BUG, "Called with unknown purpose %d", purpose);
  return "(unknown)";
}

/** Return true iff <b>identity_digest</b> is the digest of a router we
 * believe to support extrainfo downloads.  (If <b>is_authority</b> we do
 * additional checking that's only valid for authorities.) */
int
router_supports_extrainfo(const char *identity_digest, int is_authority)
{
  const node_t *node = node_get_by_id(identity_digest);

  if (node && node->ri) {
    if (node->ri->caches_extra_info)
      return 1;
  }
  if (is_authority) {
    return 1;
  }
  return 0;
}

/** Return true iff any trusted directory authority has accepted our
 * server descriptor.
 *
 * We consider any authority sufficient because waiting for all of
 * them means it never happens while any authority is down; we don't
 * go for something more complex in the middle (like \>1/3 or \>1/2 or
 * \>=1/2) because that doesn't seem necessary yet.
 */
int
directories_have_accepted_server_descriptor(void)
{
  const smartlist_t *servers = router_get_trusted_dir_servers();
  const or_options_t *options = get_options();
  SMARTLIST_FOREACH(servers, dir_server_t *, d, {
    if ((d->type & options->PublishServerDescriptor_) &&
        d->has_accepted_serverdesc) {
      return 1;
    }
  });
  return 0;
}

/** Start a connection to every suitable directory authority, using
 * connection purpose <b>dir_purpose</b> and uploading <b>payload</b>
 * (of length <b>payload_len</b>). The dir_purpose should be one of
 * 'DIR_PURPOSE_UPLOAD_DIR' or 'DIR_PURPOSE_UPLOAD_RENDDESC'.
 *
 * <b>router_purpose</b> describes the type of descriptor we're
 * publishing, if we're publishing a descriptor -- e.g. general or bridge.
 *
 * <b>type</b> specifies what sort of dir authorities (V1, V3,
 * HIDSERV, BRIDGE, etc) we should upload to.
 *
 * If <b>extrainfo_len</b> is nonzero, the first <b>payload_len</b> bytes of
 * <b>payload</b> hold a router descriptor, and the next <b>extrainfo_len</b>
 * bytes of <b>payload</b> hold an extra-info document.  Upload the descriptor
 * to all authorities, and the extra-info document to all authorities that
 * support it.
 */
void
directory_post_to_dirservers(uint8_t dir_purpose, uint8_t router_purpose,
                             dirinfo_type_t type,
                             const char *payload,
                             size_t payload_len, size_t extrainfo_len)
{
  const or_options_t *options = get_options();
  int post_via_tor;
  const smartlist_t *dirservers = router_get_trusted_dir_servers();
  int found = 0;
  const int exclude_self = (dir_purpose == DIR_PURPOSE_UPLOAD_VOTE ||
                            dir_purpose == DIR_PURPOSE_UPLOAD_SIGNATURES);
  tor_assert(dirservers);
  /* This tries dirservers which we believe to be down, but ultimately, that's
   * harmless, and we may as well err on the side of getting things uploaded.
   */
  SMARTLIST_FOREACH_BEGIN(dirservers, dir_server_t *, ds) {
      routerstatus_t *rs = &(ds->fake_status);
      size_t upload_len = payload_len;
      tor_addr_t ds_addr;

      if ((type & ds->type) == 0)
        continue;

      if (exclude_self && router_digest_is_me(ds->digest))
        continue;

      if (options->StrictNodes &&
          routerset_contains_routerstatus(options->ExcludeNodes, rs, -1)) {
        log_warn(LD_DIR, "Wanted to contact authority '%s' for %s, but "
                 "it's in our ExcludedNodes list and StrictNodes is set. "
                 "Skipping.",
                 ds->nickname,
                 dir_conn_purpose_to_string(dir_purpose));
        continue;
      }

      found = 1; /* at least one authority of this type was listed */
      if (dir_purpose == DIR_PURPOSE_UPLOAD_DIR)
        ds->has_accepted_serverdesc = 0;

      if (extrainfo_len && router_supports_extrainfo(ds->digest, 1)) {
        upload_len += extrainfo_len;
        log_info(LD_DIR, "Uploading an extrainfo too (length %d)",
                 (int) extrainfo_len);
      }
      tor_addr_from_ipv4h(&ds_addr, ds->addr);
      post_via_tor = purpose_needs_anonymity(dir_purpose, router_purpose) ||
        !fascist_firewall_allows_address_dir(&ds_addr, ds->dir_port);
      directory_initiate_command_routerstatus(rs, dir_purpose,
                                              router_purpose,
                                              post_via_tor,
                                              NULL, payload, upload_len, 0);
  } SMARTLIST_FOREACH_END(ds);
  if (!found) {
    char *s = authdir_type_to_string(type);
    log_warn(LD_DIR, "Publishing server descriptor to directory authorities "
             "of type '%s', but no authorities of that type listed!", s);
    tor_free(s);
  }
}

/** Return true iff, according to the values in <b>options</b>, we should be
 * using directory guards for direct downloads of directory information. */
static int
should_use_directory_guards(const or_options_t *options)
{
  /* Public (non-bridge) servers never use directory guards. */
  if (public_server_mode(options))
    return 0;
  /* If guards are disabled, or directory guards are disabled, we can't
   * use directory guards.
   */
  if (!options->UseEntryGuards || !options->UseEntryGuardsAsDirGuards)
    return 0;
  /* If we're configured to fetch directory info aggressively or of a
   * nonstandard type, don't use directory guards. */
  if (options->DownloadExtraInfo || options->FetchDirInfoEarly ||
      options->FetchDirInfoExtraEarly || options->FetchUselessDescriptors)
    return 0;
  if (! options->PreferTunneledDirConns)
    return 0;
  return 1;
}

/** Pick an unconsetrained directory server from among our guards, the latest
 * networkstatus, or the fallback dirservers, for use in downloading
 * information of type <b>type</b>, and return its routerstatus. */
static const routerstatus_t *
directory_pick_generic_dirserver(dirinfo_type_t type, int pds_flags,
                                 uint8_t dir_purpose)
{
  const routerstatus_t *rs = NULL;
  const or_options_t *options = get_options();

  if (options->UseBridges)
    log_warn(LD_BUG, "Called when we have UseBridges set.");

  if (should_use_directory_guards(options)) {
    const node_t *node = choose_random_dirguard(type);
    if (node)
      rs = node->rs;
  } else {
    /* anybody with a non-zero dirport will do */
    rs = router_pick_directory_server(type, pds_flags);
  }
  if (!rs) {
    log_info(LD_DIR, "No router found for %s; falling back to "
             "dirserver list.", dir_conn_purpose_to_string(dir_purpose));
    rs = router_pick_fallback_dirserver(type, pds_flags);
  }

  return rs;
}

/** Start a connection to a random running directory server, using
 * connection purpose <b>dir_purpose</b>, intending to fetch descriptors
 * of purpose <b>router_purpose</b>, and requesting <b>resource</b>.
 * Use <b>pds_flags</b> as arguments to router_pick_directory_server()
 * or router_pick_trusteddirserver().
 */
void
directory_get_from_dirserver(uint8_t dir_purpose, uint8_t router_purpose,
                             const char *resource, int pds_flags)
{
  const routerstatus_t *rs = NULL;
  const or_options_t *options = get_options();
  int prefer_authority = directory_fetches_from_authorities(options);
  int require_authority = 0;
  int get_via_tor = purpose_needs_anonymity(dir_purpose, router_purpose);
  dirinfo_type_t type;
  time_t if_modified_since = 0;

  /* FFFF we could break this switch into its own function, and call
   * it elsewhere in directory.c. -RD */
  switch (dir_purpose) {
    case DIR_PURPOSE_FETCH_EXTRAINFO:
      type = EXTRAINFO_DIRINFO |
             (router_purpose == ROUTER_PURPOSE_BRIDGE ? BRIDGE_DIRINFO :
                                                        V3_DIRINFO);
      break;
    case DIR_PURPOSE_FETCH_SERVERDESC:
      type = (router_purpose == ROUTER_PURPOSE_BRIDGE ? BRIDGE_DIRINFO :
                                                        V3_DIRINFO);
      break;
    case DIR_PURPOSE_FETCH_RENDDESC:
      type = HIDSERV_DIRINFO;
      break;
    case DIR_PURPOSE_FETCH_STATUS_VOTE:
    case DIR_PURPOSE_FETCH_DETACHED_SIGNATURES:
    case DIR_PURPOSE_FETCH_CERTIFICATE:
      type = V3_DIRINFO;
      break;
    case DIR_PURPOSE_FETCH_CONSENSUS:
      type = V3_DIRINFO;
      if (resource && !strcmp(resource,"microdesc"))
        type |= MICRODESC_DIRINFO;
      break;
    case DIR_PURPOSE_FETCH_MICRODESC:
      type = MICRODESC_DIRINFO;
      break;
    default:
      log_warn(LD_BUG, "Unexpected purpose %d", (int)dir_purpose);
      return;
  }

  if (dir_purpose == DIR_PURPOSE_FETCH_CONSENSUS) {
    int flav = FLAV_NS;
    networkstatus_t *v;
    if (resource)
      flav = networkstatus_parse_flavor_name(resource);

    if (flav != -1) {
      /* IF we have a parsed consensus of this type, we can do an
       * if-modified-time based on it. */
      v = networkstatus_get_latest_consensus_by_flavor(flav);
      if (v)
        if_modified_since = v->valid_after + 180;
    } else {
      /* Otherwise it might be a consensus we don't parse, but which we
       * do cache.  Look at the cached copy, perhaps. */
      cached_dir_t *cd = dirserv_get_consensus(resource);
      if (cd)
        if_modified_since = cd->published + 180;
    }
  }

  if (!options->FetchServerDescriptors && type != HIDSERV_DIRINFO)
    return;

  if (!get_via_tor) {
    if (options->UseBridges && type != BRIDGE_DIRINFO) {
      /* We want to ask a running bridge for which we have a descriptor.
       *
       * When we ask choose_random_entry() for a bridge, we specify what
       * sort of dir fetch we'll be doing, so it won't return a bridge
       * that can't answer our question.
       */
      /* XXX024 Not all bridges handle conditional consensus downloading,
       * so, for now, never assume the server supports that. -PP */
      const node_t *node = choose_random_dirguard(type);
      if (node && node->ri) {
        /* every bridge has a routerinfo. */
        tor_addr_t addr;
        routerinfo_t *ri = node->ri;
        node_get_addr(node, &addr);
        directory_initiate_command(ri->address, &addr,
                                   ri->or_port, 0/*no dirport*/,
                                   ri->cache_info.identity_digest,
                                   dir_purpose,
                                   router_purpose,
                                   DIRIND_ONEHOP,
                                   resource, NULL, 0, if_modified_since);
      } else
        log_notice(LD_DIR, "Ignoring directory request, since no bridge "
                           "nodes are available yet.");
      return;
    } else {
      if (prefer_authority || type == BRIDGE_DIRINFO) {
        /* only ask authdirservers, and don't ask myself */
        rs = router_pick_trusteddirserver(type, pds_flags);
        if (rs == NULL && (pds_flags & (PDS_NO_EXISTING_SERVERDESC_FETCH|
                                        PDS_NO_EXISTING_MICRODESC_FETCH))) {
          /* We don't want to fetch from any authorities that we're currently
           * fetching server descriptors from, and we got no match.  Did we
           * get no match because all the authorities have connections
           * fetching server descriptors (in which case we should just
           * return,) or because all the authorities are down or on fire or
           * unreachable or something (in which case we should go on with
           * our fallback code)? */
          pds_flags &= ~(PDS_NO_EXISTING_SERVERDESC_FETCH|
                         PDS_NO_EXISTING_MICRODESC_FETCH);
          rs = router_pick_trusteddirserver(type, pds_flags);
          if (rs) {
            log_debug(LD_DIR, "Deferring serverdesc fetch: all authorities "
                      "are in use.");
            return;
          }
        }
        if (rs == NULL && require_authority) {
          log_info(LD_DIR, "No authorities were available for %s: will try "
                   "later.", dir_conn_purpose_to_string(dir_purpose));
          return;
        }
      }
      if (!rs && type != BRIDGE_DIRINFO) {
        /* */
        rs = directory_pick_generic_dirserver(type, pds_flags,
                                              dir_purpose);
        if (!rs) {
          /*XXXX024 I'm pretty sure this can never do any good, since
           * rs isn't set. */
          get_via_tor = 1; /* last resort: try routing it via Tor */
        }
      }
    }
  } else { /* get_via_tor */
    /* Never use fascistfirewall; we're going via Tor. */
    if (dir_purpose == DIR_PURPOSE_FETCH_RENDDESC) {
      /* only ask hidserv authorities, any of them will do */
      pds_flags |= PDS_IGNORE_FASCISTFIREWALL|PDS_ALLOW_SELF;
      rs = router_pick_trusteddirserver(HIDSERV_DIRINFO, pds_flags);
    } else {
      /* anybody with a non-zero dirport will do. Disregard firewalls. */
      pds_flags |= PDS_IGNORE_FASCISTFIREWALL;
      rs = router_pick_directory_server(type, pds_flags);
      /* If we have any hope of building an indirect conn, we know some router
       * descriptors.  If (rs==NULL), we can't build circuits anyway, so
       * there's no point in falling back to the authorities in this case. */
    }
  }

  if (rs) {
    const dir_indirection_t indirection =
      get_via_tor ? DIRIND_ANONYMOUS : DIRIND_ONEHOP;
    directory_initiate_command_routerstatus(rs, dir_purpose,
                                            router_purpose,
                                            indirection,
                                            resource, NULL, 0,
                                            if_modified_since);
  } else {
    log_notice(LD_DIR,
               "While fetching directory info, "
               "no running dirservers known. Will try again later. "
               "(purpose %d)", dir_purpose);
    if (!purpose_needs_anonymity(dir_purpose, router_purpose)) {
      /* remember we tried them all and failed. */
      directory_all_unreachable(time(NULL));
    }
  }
}

/** As directory_get_from_dirserver, but initiates a request to <i>every</i>
 * directory authority other than ourself.  Only for use by authorities when
 * searching for missing information while voting. */
void
directory_get_from_all_authorities(uint8_t dir_purpose,
                                   uint8_t router_purpose,
                                   const char *resource)
{
  tor_assert(dir_purpose == DIR_PURPOSE_FETCH_STATUS_VOTE ||
             dir_purpose == DIR_PURPOSE_FETCH_DETACHED_SIGNATURES);

  SMARTLIST_FOREACH_BEGIN(router_get_trusted_dir_servers(),
                          dir_server_t *, ds) {
      routerstatus_t *rs;
      if (router_digest_is_me(ds->digest))
        continue;
      if (!(ds->type & V3_DIRINFO))
        continue;
      rs = &ds->fake_status;
      directory_initiate_command_routerstatus(rs, dir_purpose, router_purpose,
                                              DIRIND_ONEHOP, resource, NULL,
                                              0, 0);
  } SMARTLIST_FOREACH_END(ds);
}

/** Return true iff <b>ind</b> requires a multihop circuit. */
static int
dirind_is_anon(dir_indirection_t ind)
{
  return ind == DIRIND_ANON_DIRPORT || ind == DIRIND_ANONYMOUS;
}

/** Same as directory_initiate_command_routerstatus(), but accepts
 * rendezvous data to fetch a hidden service descriptor. */
void
directory_initiate_command_routerstatus_rend(const routerstatus_t *status,
                                             uint8_t dir_purpose,
                                             uint8_t router_purpose,
                                             dir_indirection_t indirection,
                                             const char *resource,
                                             const char *payload,
                                             size_t payload_len,
                                             time_t if_modified_since,
                                             const rend_data_t *rend_query)
{
  const or_options_t *options = get_options();
  const node_t *node;
  char address_buf[INET_NTOA_BUF_LEN+1];
  struct in_addr in;
  const char *address;
  tor_addr_t addr;
  const int anonymized_connection = dirind_is_anon(indirection);
  node = node_get_by_id(status->identity_digest);

  if (!node && anonymized_connection) {
    log_info(LD_DIR, "Not sending anonymized request to directory '%s'; we "
             "don't have its router descriptor.",
             routerstatus_describe(status));
    return;
  } else if (node) {
    node_get_address_string(node, address_buf, sizeof(address_buf));
    address = address_buf;
  } else {
    in.s_addr = htonl(status->addr);
    tor_inet_ntoa(&in, address_buf, sizeof(address_buf));
    address = address_buf;
  }
  tor_addr_from_ipv4h(&addr, status->addr);

  if (options->ExcludeNodes && options->StrictNodes &&
      routerset_contains_routerstatus(options->ExcludeNodes, status, -1)) {
    log_warn(LD_DIR, "Wanted to contact directory mirror %s for %s, but "
             "it's in our ExcludedNodes list and StrictNodes is set. "
             "Skipping. This choice might make your Tor not work.",
             routerstatus_describe(status),
             dir_conn_purpose_to_string(dir_purpose));
    return;
  }

  directory_initiate_command_rend(address, &addr,
                             status->or_port, status->dir_port,
                             status->identity_digest,
                             dir_purpose, router_purpose,
                             indirection, resource,
                             payload, payload_len, if_modified_since,
                             rend_query);
}

/** Launch a new connection to the directory server <b>status</b> to
 * upload or download a server or rendezvous
 * descriptor. <b>dir_purpose</b> determines what
 * kind of directory connection we're launching, and must be one of
 * DIR_PURPOSE_{FETCH|UPLOAD}_{DIR|RENDDESC|RENDDESC_V2}. <b>router_purpose</b>
 * specifies the descriptor purposes we have in mind (currently only
 * used for FETCH_DIR).
 *
 * When uploading, <b>payload</b> and <b>payload_len</b> determine the content
 * of the HTTP post.  Otherwise, <b>payload</b> should be NULL.
 *
 * When fetching a rendezvous descriptor, <b>resource</b> is the service ID we
 * want to fetch.
 */
void
directory_initiate_command_routerstatus(const routerstatus_t *status,
                                        uint8_t dir_purpose,
                                        uint8_t router_purpose,
                                        dir_indirection_t indirection,
                                        const char *resource,
                                        const char *payload,
                                        size_t payload_len,
                                        time_t if_modified_since)
{
  directory_initiate_command_routerstatus_rend(status, dir_purpose,
                                          router_purpose,
                                          indirection, resource,
                                          payload, payload_len,
                                          if_modified_since, NULL);
}

/** Return true iff <b>conn</b> is the client side of a directory connection
 * we launched to ourself in order to determine the reachability of our
 * dir_port. */
static int
directory_conn_is_self_reachability_test(dir_connection_t *conn)
{
  if (conn->requested_resource &&
      !strcmpstart(conn->requested_resource,"authority")) {
    const routerinfo_t *me = router_get_my_routerinfo();
    if (me &&
        router_digest_is_me(conn->identity_digest) &&
        tor_addr_eq_ipv4h(&conn->base_.addr, me->addr) && /*XXXX prop 118*/
        me->dir_port == conn->base_.port)
      return 1;
  }
  return 0;
}

/** Called when we are unable to complete the client's request to a directory
 * server due to a network error: Mark the router as down and try again if
 * possible.
 */
static void
connection_dir_request_failed(dir_connection_t *conn)
{
  if (directory_conn_is_self_reachability_test(conn)) {
    return; /* this was a test fetch. don't retry. */
  }
  if (!entry_list_is_constrained(get_options()))
    router_set_status(conn->identity_digest, 0); /* don't try him again */
  if (conn->base_.purpose == DIR_PURPOSE_FETCH_SERVERDESC ||
             conn->base_.purpose == DIR_PURPOSE_FETCH_EXTRAINFO) {
    log_info(LD_DIR, "Giving up on serverdesc/extrainfo fetch from "
             "directory server at '%s'; retrying",
             conn->base_.address);
    if (conn->router_purpose == ROUTER_PURPOSE_BRIDGE)
      connection_dir_bridge_routerdesc_failed(conn);
    connection_dir_download_routerdesc_failed(conn);
  } else if (conn->base_.purpose == DIR_PURPOSE_FETCH_CONSENSUS) {
    if (conn->requested_resource)
      networkstatus_consensus_download_failed(0, conn->requested_resource);
  } else if (conn->base_.purpose == DIR_PURPOSE_FETCH_CERTIFICATE) {
    log_info(LD_DIR, "Giving up on certificate fetch from directory server "
             "at '%s'; retrying",
             conn->base_.address);
    connection_dir_download_cert_failed(conn, 0);
  } else if (conn->base_.purpose == DIR_PURPOSE_FETCH_DETACHED_SIGNATURES) {
    log_info(LD_DIR, "Giving up downloading detached signatures from '%s'",
             conn->base_.address);
  } else if (conn->base_.purpose == DIR_PURPOSE_FETCH_STATUS_VOTE) {
    log_info(LD_DIR, "Giving up downloading votes from '%s'",
             conn->base_.address);
  } else if (conn->base_.purpose == DIR_PURPOSE_FETCH_MICRODESC) {
    log_info(LD_DIR, "Giving up on downloading microdescriptors from "
             "directory server at '%s'; will retry", conn->base_.address);
    connection_dir_download_routerdesc_failed(conn);
  }
}

/** Helper: Attempt to fetch directly the descriptors of each bridge
 * listed in <b>failed</b>.
 */
static void
connection_dir_retry_bridges(smartlist_t *descs)
{
  char digest[DIGEST_LEN];
  SMARTLIST_FOREACH(descs, const char *, cp,
  {
    if (base16_decode(digest, DIGEST_LEN, cp, strlen(cp))<0) {
      log_warn(LD_BUG, "Malformed fingerprint in list: %s",
              escaped(cp));
      continue;
    }
    retry_bridge_descriptor_fetch_directly(digest);
  });
}

/** Called when an attempt to download one or more router descriptors
 * or extra-info documents on connection <b>conn</b> failed.
 */
static void
connection_dir_download_routerdesc_failed(dir_connection_t *conn)
{
  /* No need to increment the failure count for routerdescs, since
   * it's not their fault. */

  /* No need to relaunch descriptor downloads here: we already do it
   * every 10 or 60 seconds (FOO_DESCRIPTOR_RETRY_INTERVAL) in onion_main.c. */
  tor_assert(conn->base_.purpose == DIR_PURPOSE_FETCH_SERVERDESC ||
             conn->base_.purpose == DIR_PURPOSE_FETCH_EXTRAINFO ||
             conn->base_.purpose == DIR_PURPOSE_FETCH_MICRODESC);

  (void) conn;
}

/** Called when an attempt to download a bridge's routerdesc from
 * one of the authorities failed due to a network error. If
 * possible attempt to download descriptors from the bridge directly.
 */
static void
connection_dir_bridge_routerdesc_failed(dir_connection_t *conn)
{
  smartlist_t *which = NULL;

  /* Requests for bridge descriptors are in the form 'fp/', so ignore
     anything else. */
  if (!conn->requested_resource || strcmpstart(conn->requested_resource,"fp/"))
    return;

  which = smartlist_new();
  dir_split_resource_into_fingerprints(conn->requested_resource
                                        + strlen("fp/"),
                                       which, NULL, 0);

  tor_assert(conn->base_.purpose != DIR_PURPOSE_FETCH_EXTRAINFO);
  if (smartlist_len(which)) {
    connection_dir_retry_bridges(which);
    SMARTLIST_FOREACH(which, char *, cp, tor_free(cp));
  }
  smartlist_free(which);
}

/** Called when an attempt to fetch a certificate fails. */
static void
connection_dir_download_cert_failed(dir_connection_t *conn, int status)
{
  const char *fp_pfx = "fp/";
  const char *fpsk_pfx = "fp-sk/";
  smartlist_t *failed;
  tor_assert(conn->base_.purpose == DIR_PURPOSE_FETCH_CERTIFICATE);

  if (!conn->requested_resource)
    return;
  failed = smartlist_new();
  /*
   * We have two cases download by fingerprint (resource starts
   * with "fp/") or download by fingerprint/signing key pair
   * (resource starts with "fp-sk/").
   */
  if (!strcmpstart(conn->requested_resource, fp_pfx)) {
    /* Download by fingerprint case */
    dir_split_resource_into_fingerprints(conn->requested_resource +
                                         strlen(fp_pfx),
                                         failed, NULL, DSR_HEX);
    SMARTLIST_FOREACH_BEGIN(failed, char *, cp) {
      /* Null signing key digest indicates download by fp only */
      authority_cert_dl_failed(cp, NULL, status);
      tor_free(cp);
    } SMARTLIST_FOREACH_END(cp);
  } else if (!strcmpstart(conn->requested_resource, fpsk_pfx)) {
    /* Download by (fp,sk) pairs */
    dir_split_resource_into_fingerprint_pairs(conn->requested_resource +
                                              strlen(fpsk_pfx), failed);
    SMARTLIST_FOREACH_BEGIN(failed, fp_pair_t *, cp) {
      authority_cert_dl_failed(cp->first, cp->second, status);
      tor_free(cp);
    } SMARTLIST_FOREACH_END(cp);
  } else {
    log_warn(LD_DIR,
             "Don't know what to do with failure for cert fetch %s",
             conn->requested_resource);
  }

  smartlist_free(failed);

  update_certificate_downloads(time(NULL));
}

/** Evaluate the situation and decide if we should use an encrypted
 * "begindir-style" connection for this directory request.
 * 1) If or_port is 0, or it's a direct conn and or_port is firewalled
 *    or we're a dir mirror, no.
 * 2) If we prefer to avoid begindir conns, and we're not fetching or
 *    publishing a bridge relay descriptor, no.
 * 3) Else yes.
 */
static int
directory_command_should_use_begindir(const or_options_t *options,
                                      const tor_addr_t *addr,
                                      int or_port, uint8_t router_purpose,
                                      dir_indirection_t indirection)
{
  if (!or_port)
    return 0; /* We don't know an ORPort -- no chance. */
  if (indirection == DIRIND_DIRECT_CONN || indirection == DIRIND_ANON_DIRPORT)
    return 0;
  if (indirection == DIRIND_ONEHOP)
    if (!fascist_firewall_allows_address_or(addr, or_port) ||
        directory_fetches_from_authorities(options))
      return 0; /* We're firewalled or are acting like a relay -- also no. */
  if (!options->TunnelDirConns &&
      router_purpose != ROUTER_PURPOSE_BRIDGE)
    return 0; /* We prefer to avoid using begindir conns. Fine. */
  return 1;
}

/** Helper for directory_initiate_command_routerstatus: send the
 * command to a server whose address is <b>address</b>, whose IP is
 * <b>addr</b>, whose directory port is <b>dir_port</b>, whose tor version
 * <b>supports_begindir</b>, and whose identity key digest is
 * <b>digest</b>. */
void
directory_initiate_command(const char *address, const tor_addr_t *_addr,
                           uint16_t or_port, uint16_t dir_port,
                           const char *digest,
                           uint8_t dir_purpose, uint8_t router_purpose,
                           dir_indirection_t indirection, const char *resource,
                           const char *payload, size_t payload_len,
                           time_t if_modified_since)
{
  directory_initiate_command_rend(address, _addr, or_port, dir_port,
                             digest, dir_purpose,
                             router_purpose, indirection,
                             resource, payload, payload_len,
                             if_modified_since, NULL);
}

/** Return non-zero iff a directory connection with purpose
 * <b>dir_purpose</b> reveals sensitive information about a Tor
 * instance's client activities.  (Such connections must be performed
 * through normal three-hop Tor circuits.) */
static int
is_sensitive_dir_purpose(uint8_t dir_purpose)
{
  return ((dir_purpose == DIR_PURPOSE_FETCH_RENDDESC) ||
          (dir_purpose == DIR_PURPOSE_HAS_FETCHED_RENDDESC) ||
          (dir_purpose == DIR_PURPOSE_UPLOAD_RENDDESC) ||
          (dir_purpose == DIR_PURPOSE_UPLOAD_RENDDESC_V2) ||
          (dir_purpose == DIR_PURPOSE_FETCH_RENDDESC_V2));
}

/** Same as directory_initiate_command(), but accepts rendezvous data to
 * fetch a hidden service descriptor. */
static void
directory_initiate_command_rend(const char *address, const tor_addr_t *_addr,
                                uint16_t or_port, uint16_t dir_port,
                                const char *digest,
                                uint8_t dir_purpose, uint8_t router_purpose,
                                dir_indirection_t indirection,
                                const char *resource,
                                const char *payload, size_t payload_len,
                                time_t if_modified_since,
                                const rend_data_t *rend_query)
{
  dir_connection_t *conn;
  const or_options_t *options = get_options();
  int socket_error = 0;
  int use_begindir = directory_command_should_use_begindir(options, _addr,
                                     or_port, router_purpose, indirection);
  const int anonymized_connection = dirind_is_anon(indirection);
  tor_addr_t addr;

  tor_assert(address);
  tor_assert(_addr);
  tor_assert(or_port || dir_port);
  tor_assert(digest);

  tor_addr_copy(&addr, _addr);

  log_debug(LD_DIR, "anonymized %d, use_begindir %d.",
            anonymized_connection, use_begindir);

  log_debug(LD_DIR, "Initiating %s", dir_conn_purpose_to_string(dir_purpose));

#ifndef NON_ANONYMOUS_MODE_ENABLED
  tor_assert(!(is_sensitive_dir_purpose(dir_purpose) &&
               !anonymized_connection));
#else
  (void)is_sensitive_dir_purpose;
#endif

  /* ensure that we don't make direct connections when a SOCKS server is
   * configured. */
  if (!anonymized_connection && !use_begindir && !options->HTTPProxy &&
      (options->Socks4Proxy || options->Socks5Proxy)) {
    log_warn(LD_DIR, "Cannot connect to a directory server through a "
                     "SOCKS proxy!");
    return;
  }

  conn = dir_connection_new(tor_addr_family(&addr));

  /* set up conn so it's got all the data we need to remember */
  tor_addr_copy(&conn->base_.addr, &addr);
  conn->base_.port = use_begindir ? or_port : dir_port;
  conn->base_.address = tor_strdup(address);
  memcpy(conn->identity_digest, digest, DIGEST_LEN);

  conn->base_.purpose = dir_purpose;
  conn->router_purpose = router_purpose;

  /* give it an initial state */
  conn->base_.state = DIR_CONN_STATE_CONNECTING;

  /* decide whether we can learn our IP address from this conn */
  /* XXXX This is a bad name for this field now. */
  conn->dirconn_direct = !anonymized_connection;

  /* copy rendezvous data, if any */
  if (rend_query)
    conn->rend_data = rend_data_dup(rend_query);

  if (!anonymized_connection && !use_begindir) {
    /* then we want to connect to dirport directly */

    if (options->HTTPProxy) {
      tor_addr_copy(&addr, &options->HTTPProxyAddr);
      dir_port = options->HTTPProxyPort;
    }

    switch (connection_connect(TO_CONN(conn), conn->base_.address, &addr,
                               dir_port, &socket_error)) {
      case -1:
        connection_dir_request_failed(conn); /* retry if we want */
        /* XXX we only pass 'conn' above, not 'resource', 'payload',
         * etc. So in many situations it can't retry! -RD */
        connection_free(TO_CONN(conn));
        return;
      case 1:
        /* start flushing conn */
        conn->base_.state = DIR_CONN_STATE_CLIENT_SENDING;
        /* fall through */
      case 0:
        /* queue the command on the outbuf */
        directory_send_command(conn, dir_purpose, 1, resource,
                               payload, payload_len,
                               if_modified_since);
        connection_watch_events(TO_CONN(conn), READ_EVENT | WRITE_EVENT);
        /* writable indicates finish, readable indicates broken link,
           error indicates broken link in windowsland. */
    }
  } else { /* we want to connect via a tor connection */
    entry_connection_t *linked_conn;
    /* Anonymized tunneled connections can never share a circuit.
     * One-hop directory connections can share circuits with each other
     * but nothing else. */
    int iso_flags = anonymized_connection ? ISO_STREAM : ISO_SESSIONGRP;

    /* If it's an anonymized connection, remember the fact that we
     * wanted it for later: maybe we'll want it again soon. */
    if (anonymized_connection && use_begindir)
      rep_hist_note_used_internal(time(NULL), 0, 1);
    else if (anonymized_connection && !use_begindir)
      rep_hist_note_used_port(time(NULL), conn->base_.port);

    /* make an AP connection
     * populate it and add it at the right state
     * hook up both sides
     */
    linked_conn =
      connection_ap_make_link(TO_CONN(conn),
                              conn->base_.address, conn->base_.port,
                              digest,
                              SESSION_GROUP_DIRCONN, iso_flags,
                              use_begindir, conn->dirconn_direct);
    if (!linked_conn) {
      log_warn(LD_NET,"Making tunnel to dirserver failed.");
      connection_mark_for_close(TO_CONN(conn));
      return;
    }

    if (connection_add(TO_CONN(conn)) < 0) {
      log_warn(LD_NET,"Unable to add connection for link to dirserver.");
      connection_mark_for_close(TO_CONN(conn));
      return;
    }
    conn->base_.state = DIR_CONN_STATE_CLIENT_SENDING;
    /* queue the command on the outbuf */
    directory_send_command(conn, dir_purpose, 0, resource,
                           payload, payload_len,
                           if_modified_since);

    connection_watch_events(TO_CONN(conn), READ_EVENT|WRITE_EVENT);
    IF_HAS_BUFFEREVENT(ENTRY_TO_CONN(linked_conn), {
      connection_watch_events(ENTRY_TO_CONN(linked_conn),
                              READ_EVENT|WRITE_EVENT);
    }) ELSE_IF_NO_BUFFEREVENT
      connection_start_reading(ENTRY_TO_CONN(linked_conn));
  }
}

/** Return true iff anything we say on <b>conn</b> is being encrypted before
 * we send it to the client/server. */
int
connection_dir_is_encrypted(dir_connection_t *conn)
{
  /* Right now it's sufficient to see if conn is or has been linked, since
   * the only thing it could be linked to is an edge connection on a
   * circuit, and the only way it could have been unlinked is at the edge
   * connection getting closed.
   */
  return TO_CONN(conn)->linked;
}

/** Helper for sorting
 *
 * sort strings alphabetically
 */
static int
compare_strs_(const void **a, const void **b)
{
  const char *s1 = *a, *s2 = *b;
  return strcmp(s1, s2);
}

#define CONDITIONAL_CONSENSUS_FPR_LEN 3
#if (CONDITIONAL_CONSENSUS_FPR_LEN > DIGEST_LEN)
#error "conditional consensus fingerprint length is larger than digest length"
#endif

/** Return the URL we should use for a consensus download.
 *
 * This url depends on whether or not the server we go to
 * is sufficiently new to support conditional consensus downloading,
 * i.e. GET .../consensus/<b>fpr</b>+<b>fpr</b>+<b>fpr</b>
 *
 * If 'resource' is provided, it is the name of a consensus flavor to request.
 */
static char *
directory_get_consensus_url(const char *resource)
{
  char *url = NULL;
  const char *hyphen, *flavor;
  if (resource==NULL || strcmp(resource, "ns")==0) {
    flavor = ""; /* Request ns consensuses as "", so older servers will work*/
    hyphen = "";
  } else {
    flavor = resource;
    hyphen = "-";
  }

  {
    char *authority_id_list;
    smartlist_t *authority_digests = smartlist_new();

    SMARTLIST_FOREACH_BEGIN(router_get_trusted_dir_servers(),
                            dir_server_t *, ds) {
        char *hex;
        if (!(ds->type & V3_DIRINFO))
          continue;

        hex = tor_malloc(2*CONDITIONAL_CONSENSUS_FPR_LEN+1);
        base16_encode(hex, 2*CONDITIONAL_CONSENSUS_FPR_LEN+1,
                      ds->v3_identity_digest, CONDITIONAL_CONSENSUS_FPR_LEN);
        smartlist_add(authority_digests, hex);
    } SMARTLIST_FOREACH_END(ds);
    smartlist_sort(authority_digests, compare_strs_);
    authority_id_list = smartlist_join_strings(authority_digests,
                                               "+", 0, NULL);

    tor_asprintf(&url, "/tor/status-vote/current/consensus%s%s/%s.z",
                 hyphen, flavor, authority_id_list);

    SMARTLIST_FOREACH(authority_digests, char *, cp, tor_free(cp));
    smartlist_free(authority_digests);
    tor_free(authority_id_list);
  }
  return url;
}

/** Queue an appropriate HTTP command on conn-\>outbuf.  The other args
 * are as in directory_initiate_command().
 */
static void
directory_send_command(dir_connection_t *conn,
                       int purpose, int direct, const char *resource,
                       const char *payload, size_t payload_len,
                       time_t if_modified_since)
{
  char proxystring[256];
  char hoststring[128];
  smartlist_t *headers = smartlist_new();
  char *url;
  char request[8192];
  const char *httpcommand = NULL;

  tor_assert(conn);
  tor_assert(conn->base_.type == CONN_TYPE_DIR);

  tor_free(conn->requested_resource);
  if (resource)
    conn->requested_resource = tor_strdup(resource);

  /* come up with a string for which Host: we want */
  if (conn->base_.port == 80) {
    strlcpy(hoststring, conn->base_.address, sizeof(hoststring));
  } else {
    tor_snprintf(hoststring, sizeof(hoststring),"%s:%d",
                 conn->base_.address, conn->base_.port);
  }

  /* Format if-modified-since */
  if (if_modified_since) {
    char b[RFC1123_TIME_LEN+1];
    format_rfc1123_time(b, if_modified_since);
    smartlist_add_asprintf(headers, "If-Modified-Since: %s\r\n", b);
  }

  /* come up with some proxy lines, if we're using one. */
  if (direct && get_options()->HTTPProxy) {
    char *base64_authenticator=NULL;
    const char *authenticator = get_options()->HTTPProxyAuthenticator;

    tor_snprintf(proxystring, sizeof(proxystring),"http://%s", hoststring);
    if (authenticator) {
      base64_authenticator = alloc_http_authenticator(authenticator);
      if (!base64_authenticator)
        log_warn(LD_BUG, "Encoding http authenticator failed");
    }
    if (base64_authenticator) {
      smartlist_add_asprintf(headers,
                   "Proxy-Authorization: Basic %s\r\n",
                   base64_authenticator);
      tor_free(base64_authenticator);
    }
  } else {
    proxystring[0] = 0;
  }

  switch (purpose) {
    case DIR_PURPOSE_FETCH_CONSENSUS:
      /* resource is optional.  If present, it's a flavor name */
      tor_assert(!payload);
      httpcommand = "GET";
      url = directory_get_consensus_url(resource);
      log_info(LD_DIR, "Downloading consensus from %s using %s",
               hoststring, url);
      break;
    case DIR_PURPOSE_FETCH_CERTIFICATE:
      tor_assert(resource);
      tor_assert(!payload);
      httpcommand = "GET";
      tor_asprintf(&url, "/tor/keys/%s", resource);
      break;
    case DIR_PURPOSE_FETCH_STATUS_VOTE:
      tor_assert(resource);
      tor_assert(!payload);
      httpcommand = "GET";
      tor_asprintf(&url, "/tor/status-vote/next/%s.z", resource);
      break;
    case DIR_PURPOSE_FETCH_DETACHED_SIGNATURES:
      tor_assert(!resource);
      tor_assert(!payload);
      httpcommand = "GET";
      url = tor_strdup("/tor/status-vote/next/consensus-signatures.z");
      break;
    case DIR_PURPOSE_FETCH_SERVERDESC:
      tor_assert(resource);
      httpcommand = "GET";
      tor_asprintf(&url, "/tor/server/%s", resource);
      break;
    case DIR_PURPOSE_FETCH_EXTRAINFO:
      tor_assert(resource);
      httpcommand = "GET";
      tor_asprintf(&url, "/tor/extra/%s", resource);
      break;
    case DIR_PURPOSE_FETCH_MICRODESC:
      tor_assert(resource);
      httpcommand = "GET";
      tor_asprintf(&url, "/tor/micro/%s", resource);
      break;
    case DIR_PURPOSE_UPLOAD_DIR: {
      const char *why = router_get_descriptor_gen_reason();
      tor_assert(!resource);
      tor_assert(payload);
      httpcommand = "POST";
      url = tor_strdup("/tor/");
      if (why) {
        smartlist_add_asprintf(headers, "X-Desc-Gen-Reason: %s\r\n", why);
      }
      break;
    }
    case DIR_PURPOSE_UPLOAD_VOTE:
      tor_assert(!resource);
      tor_assert(payload);
      httpcommand = "POST";
      url = tor_strdup("/tor/post/vote");
      break;
    case DIR_PURPOSE_UPLOAD_SIGNATURES:
      tor_assert(!resource);
      tor_assert(payload);
      httpcommand = "POST";
      url = tor_strdup("/tor/post/consensus-signature");
      break;
    case DIR_PURPOSE_FETCH_RENDDESC_V2:
      tor_assert(resource);
      tor_assert(strlen(resource) <= REND_DESC_ID_V2_LEN_BASE32);
      tor_assert(!payload);
      httpcommand = "GET";
      tor_asprintf(&url, "/tor/rendezvous2/%s", resource);
      break;
    case DIR_PURPOSE_UPLOAD_RENDDESC:
      tor_assert(!resource);
      tor_assert(payload);
      httpcommand = "POST";
      url = tor_strdup("/tor/rendezvous/publish");
      break;
    case DIR_PURPOSE_UPLOAD_RENDDESC_V2:
      tor_assert(!resource);
      tor_assert(payload);
      httpcommand = "POST";
      url = tor_strdup("/tor/rendezvous2/publish");
      break;
    default:
      tor_assert(0);
      return;
  }

  if (strlen(proxystring) + strlen(url) >= 4096) {
    log_warn(LD_BUG,
             "Squid does not like URLs longer than 4095 bytes, and this "
             "one is %d bytes long: %s%s",
             (int)(strlen(proxystring) + strlen(url)), proxystring, url);
  }

  tor_snprintf(request, sizeof(request), "%s %s", httpcommand, proxystring);
  connection_write_to_buf(request, strlen(request), TO_CONN(conn));
  connection_write_to_buf(url, strlen(url), TO_CONN(conn));
  tor_free(url);

  if (!strcmp(httpcommand, "POST") || payload) {
    smartlist_add_asprintf(headers, "Content-Length: %lu\r\n",
                 payload ? (unsigned long)payload_len : 0);
  }

  {
    char *header = smartlist_join_strings(headers, "", 0, NULL);
    tor_snprintf(request, sizeof(request), " HTTP/1.0\r\nHost: %s\r\n%s\r\n",
                 hoststring, header);
    tor_free(header);
  }

  connection_write_to_buf(request, strlen(request), TO_CONN(conn));

  if (payload) {
    /* then send the payload afterwards too */
    connection_write_to_buf(payload, payload_len, TO_CONN(conn));
  }

  SMARTLIST_FOREACH(headers, char *, h, tor_free(h));
  smartlist_free(headers);
}

/** Parse an HTTP request string <b>headers</b> of the form
 * \verbatim
 * "\%s [http[s]://]\%s HTTP/1..."
 * \endverbatim
 * If it's well-formed, strdup the second \%s into *<b>url</b>, and
 * nul-terminate it. If the url doesn't start with "/tor/", rewrite it
 * so it does. Return 0.
 * Otherwise, return -1.
 */
STATIC int
parse_http_url(const char *headers, char **url)
{
  char *s, *start, *tmp;

  s = (char *)eat_whitespace_no_nl(headers);
  if (!*s) return -1;
  s = (char *)find_whitespace(s); /* get past GET/POST */
  if (!*s) return -1;
  s = (char *)eat_whitespace_no_nl(s);
  if (!*s) return -1;
  start = s; /* this is it, assuming it's valid */
  s = (char *)find_whitespace(start);
  if (!*s) return -1;

  /* tolerate the http[s] proxy style of putting the hostname in the url */
  if (s-start >= 4 && !strcmpstart(start,"http")) {
    tmp = start + 4;
    if (*tmp == 's')
      tmp++;
    if (s-tmp >= 3 && !strcmpstart(tmp,"://")) {
      tmp = strchr(tmp+3, '/');
      if (tmp && tmp < s) {
        log_debug(LD_DIR,"Skipping over 'http[s]://hostname/' string");
        start = tmp;
      }
    }
  }

  /* Check if the header is well formed (next sequence
   * should be HTTP/1.X\r\n). Assumes we're supporting 1.0? */
  {
    unsigned minor_ver;
    char ch;
    char *e = (char *)eat_whitespace_no_nl(s);
    if (2 != tor_sscanf(e, "HTTP/1.%u%c", &minor_ver, &ch)) {
      return -1;
    }
    if (ch != '\r')
      return -1;
  }

  if (s-start < 5 || strcmpstart(start,"/tor/")) { /* need to rewrite it */
    *url = tor_malloc(s - start + 5);
    strlcpy(*url,"/tor", s-start+5);
    strlcat((*url)+4, start, s-start+1);
  } else {
    *url = tor_strndup(start, s-start);
  }
  return 0;
}

/** Return a copy of the first HTTP header in <b>headers</b> whose key is
 * <b>which</b>.  The key should be given with a terminating colon and space;
 * this function copies everything after, up to but not including the
 * following \\r\\n. */
static char *
http_get_header(const char *headers, const char *which)
{
  const char *cp = headers;
  while (cp) {
    if (!strcasecmpstart(cp, which)) {
      char *eos;
      cp += strlen(which);
      if ((eos = strchr(cp,'\r')))
        return tor_strndup(cp, eos-cp);
      else
        return tor_strdup(cp);
    }
    cp = strchr(cp, '\n');
    if (cp)
      ++cp;
  }
  return NULL;
}

/** If <b>headers</b> indicates that a proxy was involved, then rewrite
 * <b>conn</b>-\>address to describe our best guess of the address that
 * originated this HTTP request. */
static void
http_set_address_origin(const char *headers, connection_t *conn)
{
  char *fwd;

  fwd = http_get_header(headers, "Forwarded-For: ");
  if (!fwd)
    fwd = http_get_header(headers, "X-Forwarded-For: ");
  if (fwd) {
    struct in_addr in;
    if (!tor_inet_aton(fwd, &in) || is_internal_IP(ntohl(in.s_addr), 0)) {
      log_debug(LD_DIR, "Ignoring unrecognized or internal IP %s",
                escaped(fwd));
      tor_free(fwd);
      return;
    }
    tor_free(conn->address);
    conn->address = tor_strdup(fwd);
    tor_free(fwd);
  }
}

/** Parse an HTTP response string <b>headers</b> of the form
 * \verbatim
 * "HTTP/1.\%d \%d\%s\r\n...".
 * \endverbatim
 *
 * If it's well-formed, assign the status code to *<b>code</b> and
 * return 0.  Otherwise, return -1.
 *
 * On success: If <b>date</b> is provided, set *date to the Date
 * header in the http headers, or 0 if no such header is found.  If
 * <b>compression</b> is provided, set *<b>compression</b> to the
 * compression method given in the Content-Encoding header, or 0 if no
 * such header is found, or -1 if the value of the header is not
 * recognized.  If <b>reason</b> is provided, strdup the reason string
 * into it.
 */
int
parse_http_response(const char *headers, int *code, time_t *date,
                    compress_method_t *compression, char **reason)
{
  unsigned n1, n2;
  char datestr[RFC1123_TIME_LEN+1];
  smartlist_t *parsed_headers;
  tor_assert(headers);
  tor_assert(code);

  while (TOR_ISSPACE(*headers)) headers++; /* tolerate leading whitespace */

  if (tor_sscanf(headers, "HTTP/1.%u %u", &n1, &n2) < 2 ||
      (n1 != 0 && n1 != 1) ||
      (n2 < 100 || n2 >= 600)) {
    log_warn(LD_HTTP,"Failed to parse header %s",escaped(headers));
    return -1;
  }
  *code = n2;

  parsed_headers = smartlist_new();
  smartlist_split_string(parsed_headers, headers, "\n",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, -1);
  if (reason) {
    smartlist_t *status_line_elements = smartlist_new();
    tor_assert(smartlist_len(parsed_headers));
    smartlist_split_string(status_line_elements,
                           smartlist_get(parsed_headers, 0),
                           " ", SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 3);
    tor_assert(smartlist_len(status_line_elements) <= 3);
    if (smartlist_len(status_line_elements) == 3) {
      *reason = smartlist_get(status_line_elements, 2);
      smartlist_set(status_line_elements, 2, NULL); /* Prevent free */
    }
    SMARTLIST_FOREACH(status_line_elements, char *, cp, tor_free(cp));
    smartlist_free(status_line_elements);
  }
  if (date) {
    *date = 0;
    SMARTLIST_FOREACH(parsed_headers, const char *, s,
      if (!strcmpstart(s, "Date: ")) {
        strlcpy(datestr, s+6, sizeof(datestr));
        /* This will do nothing on failure, so we don't need to check
           the result.   We shouldn't warn, since there are many other valid
           date formats besides the one we use. */
        parse_rfc1123_time(datestr, date);
        break;
      });
  }
  if (compression) {
    const char *enc = NULL;
    SMARTLIST_FOREACH(parsed_headers, const char *, s,
      if (!strcmpstart(s, "Content-Encoding: ")) {
        enc = s+18; break;
      });
    if (!enc || !strcmp(enc, "identity")) {
      *compression = NO_METHOD;
    } else if (!strcmp(enc, "deflate") || !strcmp(enc, "x-deflate")) {
      *compress