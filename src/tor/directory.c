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
                                const rend