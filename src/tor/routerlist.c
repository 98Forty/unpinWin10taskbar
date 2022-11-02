/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file routerlist.c
 * \brief Code to
 * maintain and access the global list of routerinfos for known
 * servers.
 **/

#define ROUTERLIST_PRIVATE
#include "or.h"
#include "circuitstats.h"
#include "config.h"
#include "connection.h"
#include "control.h"
#include "directory.h"
#include "dirserv.h"
#include "dirvote.h"
#include "entrynodes.h"
#include "fp_pair.h"
#include "geoip.h"
#include "hibernate.h"
#include "onion_main.h"
#include "microdesc.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "policies.h"
#include "reasons.h"
#include "rendcommon.h"
#include "rendservice.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"
#include "routerparse.h"
#include "routerset.h"
#include "sandbox.h"
// #define DEBUG_ROUTERLIST

/****************************************************************************/

DECLARE_TYPED_DIGESTMAP_FNS(sdmap_, digest_sd_map_t, signed_descriptor_t)
DECLARE_TYPED_DIGESTMAP_FNS(rimap_, digest_ri_map_t, routerinfo_t)
DECLARE_TYPED_DIGESTMAP_FNS(eimap_, digest_ei_map_t, extrainfo_t)
DECLARE_TYPED_DIGESTMAP_FNS(dsmap_, digest_ds_map_t, download_status_t)
#define SDMAP_FOREACH(map, keyvar, valvar)                              \
  DIGESTMAP_FOREACH(sdmap_to_digestmap(map), keyvar, signed_descriptor_t *, \
                    valvar)
#define RIMAP_FOREACH(map, keyvar, valvar) \
  DIGESTMAP_FOREACH(rimap_to_digestmap(map), keyvar, routerinfo_t *, valvar)
#define EIMAP_FOREACH(map, keyvar, valvar) \
  DIGESTMAP_FOREACH(eimap_to_digestmap(map), keyvar, extrainfo_t *, valvar)
#define DSMAP_FOREACH(map, keyvar, valvar) \
  DIGESTMAP_FOREACH(dsmap_to_digestmap(map), keyvar, download_status_t *, \
                    valvar)

/* Forward declaration for cert_list_t */
typedef struct cert_list_t cert_list_t;

/* static function prototypes */
static int compute_weighted_bandwidths(const smartlist_t *sl,
                                       bandwidth_weight_rule_t rule,
                                       u64_dbl_t **bandwidths_out);
static const routerstatus_t *router_pick_directory_server_impl(
                                           dirinfo_type_t auth, int flags);
static const routerstatus_t *router_pick_trusteddirserver_impl(
                const smartlist_t *sourcelist, dirinfo_type_t auth,
                int flags, int *n_busy_out);
static const routerstatus_t *router_pick_dirserver_generic(
                              smartlist_t *sourcelist,
                              dirinfo_type_t type, int flags);
static void mark_all_dirservers_up(smartlist_t *server_list);
static void dir_server_free(dir_server_t *ds);
static int signed_desc_digest_is_recognized(signed_descriptor_t *desc);
static const char *signed_descriptor_get_body_impl(
                                              const signed_descriptor_t *desc,
                                              int with_annotations);
static void list_pending_downloads(digestmap_t *result,
                                   int purpose, const char *prefix);
static void list_pending_fpsk_downloads(fp_pair_map_t *result);
static void launch_dummy_descriptor_download_as_needed(time_t now,
                                   const or_options_t *options);
static void download_status_reset_by_sk_in_cl(cert_list_t *cl,
                                              const char *digest);
static int download_status_is_ready_by_sk_in_cl(cert_list_t *cl,
                                                const char *digest,
                                                time_t now, int max_failures);

/****************************************************************************/

/** Global list of a dir_server_t object for each directory
 * authority. */
static smartlist_t *trusted_dir_servers = NULL;
/** Global list of dir_server_t objects for all directory authorities
 * and all fallback directory servers. */
static smartlist_t *fallback_dir_servers = NULL;

/** List of for a given authority, and download status for latest certificate.
 */
struct cert_list_t {
  /*
   * The keys of download status map are cert->signing_key_digest for pending
   * downloads by (identity digest/signing key digest) pair; functions such
   * as authority_cert_get_by_digest() already assume these are unique.
   */
  struct digest_ds_map_t *dl_status_map;
  /* There is also a dlstatus for the download by identity key only */
  download_status_t dl_status_by_id;
  smartlist_t *certs;
};
/** Map from v3 identity key digest to cert_list_t. */
static digestmap_t *trusted_dir_certs = NULL;
/** True iff any key certificate in at least one member of
 * <b>trusted_dir_certs</b> has changed since we last flushed the
 * certificates to disk. */
static int trusted_dir_servers_certs_changed = 0;

/** Global list of all of the routers that we know about. */
static routerlist_t *routerlist = NULL;

/** List of strings for nicknames we've already warned about and that are
 * still unknown / unavailable. */
static smartlist_t *warned_nicknames = NULL;

/** The last time we tried to download any routerdesc, or 0 for "never".  We
 * use this to rate-limit download attempts when the number of routerdescs to
 * download is low. */
static time_t last_descriptor_download_attempted = 0;

/** When we last computed the weights to use for bandwidths on directory
 * requests, what were the total weighted bandwidth, and our share of that
 * bandwidth?  Used to determine what fraction of directory requests we should
 * expect to see.
 *
 * @{ */
static uint64_t sl_last_total_weighted_bw = 0,
  sl_last_weighted_bw_of_me = 0;
/**@}*/

/** Return the number of directory authorities whose type matches some bit set
 * in <b>type</b>  */
int
get_n_authorities(dirinfo_type_t type)
{
  int n = 0;
  if (!trusted_dir_servers)
    return 0;
  SMARTLIST_FOREACH(trusted_dir_servers, dir_server_t *, ds,
                    if (ds->type & type)
                      ++n);
  return n;
}

/** Reset the download status of a specified element in a dsmap */
static void
download_status_reset_by_sk_in_cl(cert_list_t *cl, const char *digest)
{
  download_status_t *dlstatus = NULL;

  tor_assert(cl);
  tor_assert(digest);

  /* Make sure we have a dsmap */
  if (!(cl->dl_status_map)) {
    cl->dl_status_map = dsmap_new();
  }
  /* Look for a download_status_t in the map with this digest */
  dlstatus = dsmap_get(cl->dl_status_map, digest);
  /* Got one? */
  if (!dlstatus) {
    /* Insert before we reset */
    dlstatus = tor_malloc_zero(sizeof(*dlstatus));
    dsmap_set(cl->dl_status_map, digest, dlstatus);
  }
  tor_assert(dlstatus);
  /* Go ahead and reset it */
  download_status_reset(dlstatus);
}

/**
 * Return true if the download for this signing key digest in cl is ready
 * to be re-attempted.
 */
static int
download_status_is_ready_by_sk_in_cl(cert_list_t *cl,
                                     const char *digest,
                                     time_t now, int max_failures)
{
  int rv = 0;
  download_status_t *dlstatus = NULL;

  tor_assert(cl);
  tor_assert(digest);

  /* Make sure we have a dsmap */
  if (!(cl->dl_status_map)) {
    cl->dl_status_map = dsmap_new();
  }
  /* Look for a download_status_t in the map with this digest */
  dlstatus = dsmap_get(cl->dl_status_map, digest);
  /* Got one? */
  if (dlstatus) {
    /* Use download_status_is_ready() */
    rv = download_status_is_ready(dlstatus, now, max_failures);
  } else {
    /*
     * If we don't know anything about it, return 1, since we haven't
     * tried this one before.  We need to create a new entry here,
     * too.
     */
    dlstatus = tor_malloc_zero(sizeof(*dlstatus));
    download_status_reset(dlstatus);
    dsmap_set(cl->dl_status_map, digest, dlstatus);
    rv = 1;
  }

  return rv;
}

/** Helper: Return the cert_list_t for an authority whose authority ID is
 * <b>id_digest</b>, allocating a new list if necessary. */
static cert_list_t *
get_cert_list(const char *id_digest)
{
  cert_list_t *cl;
  if (!trusted_dir_certs)
    trusted_dir_certs = digestmap_new();
  cl = digestmap_get(trusted_dir_certs, id_digest);
  if (!cl) {
    cl = tor_malloc_zero(sizeof(cert_list_t));
    cl->dl_status_by_id.schedule = DL_SCHED_CONSENSUS;
    cl->certs = smartlist_new();
    cl->dl_status_map = dsmap_new();
    digestmap_set(trusted_dir_certs, id_digest, cl);
  }
  return cl;
}

/** Release all space held by a cert_list_t */
static void
cert_list_free(cert_list_t *cl)
{
  if (!cl)
    return;

  SMARTLIST_FOREACH(cl->certs, authority_cert_t *, cert,
                    authority_cert_free(cert));
  smartlist_free(cl->certs);
  dsmap_free(cl->dl_status_map, tor_free_);
  tor_free(cl);
}

/** Wrapper for cert_list_free so we can pass it to digestmap_free */
static void
cert_list_free_(void *cl)
{
  cert_list_free(cl);
}

/** Reload the cached v3 key certificates from the cached-certs file in
 * the data directory. Return 0 on success, -1 on failure. */
int
trusted_dirs_reload_certs(void)
{
  char *filename;
  char *contents;
  int r;

  filename = get_datadir_fname("cached-certs");
  contents = read_file_to_str(filename, RFTS_IGNORE_MISSING, NULL);
  tor_free(filename);
  if (!contents)
    return 0;
  r = trusted_dirs_load_certs_from_string(
        contents,
        TRUSTED_DIRS_CERTS_SRC_FROM_STORE, 1);
  tor_free(contents);
  return r;
}

/** Helper: return true iff we already have loaded the exact cert
 * <b>cert</b>. */
static INLINE int
already_have_cert(authority_cert_t *cert)
{
  cert_list_t *cl = get_cert_list(cert->cache_info.identity_digest);

  SMARTLIST_FOREACH(cl->certs, authority_cert_t *, c,
  {
    if (tor_memeq(c->cache_info.signed_descriptor_digest,
                cert->cache_info.signed_descriptor_digest,
                DIGEST_LEN))
      return 1;
  });
  return 0;
}

/** Load a bunch of new key certificates from the string <b>contents</b>.  If
 * <b>source</b> is TRUSTED_DIRS_CERTS_SRC_FROM_STORE, the certificates are
 * from the cache, and we don't need to flush them to disk.  If we are a
 * dirauth loading our own cert, source is TRUSTED_DIRS_CERTS_SRC_SELF.
 * Otherwise, source is download type: TRUSTED_DIRS_CERTS_SRC_DL_BY_ID_DIGEST
 * or TRUSTED_DIRS_CERTS_SRC_DL_BY_ID_SK_DIGEST.  If <b>flush</b> is true, we
 * need to flush any changed certificates to disk now.  Return 0 on success,
 * -1 if any certs fail to parse.
 */

int
trusted_dirs_load_certs_from_string(const char *contents, int source,
                                    int flush)
{
  dir_server_t *ds;
  const char *s, *eos;
  int failure_code = 0;
  int from_store = (source == TRUSTED_DIRS_CERTS_SRC_FROM_STORE);

  for (s = contents; *s; s = eos) {
    authority_cert_t *cert = authority_cert_parse_from_string(s, &eos);
    cert_list_t *cl;
    if (!cert) {
      failure_code = -1;
      break;
    }
    ds = trusteddirserver_get_by_v3_auth_digest(
                                       cert->cache_info.identity_digest);
    log_debug(LD_DIR, "Parsed certificate for %s",
              ds ? ds->nickname : "unknown authority");

    if (already_have_cert(cert)) {
      /* we already have this one. continue. */
      log_info(LD_DIR, "Skipping %s certificate for %s that we "
               "already have.",
               from_store ? "cached" : "downloaded",
               ds ? ds->nickname : "an old or new authority");

      /*
       * A duplicate on download should be treated as a failure, so we call
       * authority_cert_dl_failed() to reset the download status to make sure
       * we can't try again.  Since we've implemented the fp-sk mechanism
       * to download certs by signing key, this should be much rarer than it
       * was and is perhaps cause for concern.
       */
      if (!from_store) {
        if (authdir_mode(get_options())) {
          log_warn(LD_DIR,
                   "Got a certificate for %s, but we already have it. "
                   "Maybe they haven't updated it. Waiting for a while.",
                   ds ? ds->nickname : "an old or new authority");
        } else {
          log_info(LD_DIR,
                   "Got a certificate for %s, but we already have it. "
                   "Maybe they haven't updated it. Waiting for a while.",
                   ds ? ds->nickname : "an old or new authority");
        }

        /*
         * This is where we care about the source; authority_cert_dl_failed()
         * needs to know whether the download was by fp or (fp,sk) pair to
         * twiddle the right bit in the download map.
         */
        if (source == TRUSTED_DIRS_CERTS_SRC_DL_BY_ID_DIGEST) {
          authority_cert_dl_failed(cert->cache_info.identity_digest,
                                   NULL, 404);
        } else if (source == TRUSTED_DIRS_CERTS_SRC_DL_BY_ID_SK_DIGEST) {
          authority_cert_dl_failed(cert->cache_info.identity_digest,
                                   cert->signing_key_digest, 404);
        }
      }

      authority_cert_free(cert);
      continue;
    }

    if (ds) {
      log_info(LD_DIR, "Adding %s certificate for directory authority %s with "
               "signing key %s", from_store ? "cached" : "downloaded",
               ds->nickname, hex_str(cert->signing_key_digest,DIGEST_LEN));
    } else {
      int adding = directory_caches_unknown_auth_certs(get_options());
      log_info(LD_DIR, "%s %s certificate for unrecognized directory "
               "authority with signing key %s",
               adding ? "Adding" : "Not adding",
               from_store ? "cached" : "downloaded",
               hex_str(cert->signing_key_digest,DIGEST_LEN));
      if (!adding) {
        authority_cert_free(cert);
        continue;
      }
    }

    cl = get_cert_list(cert->cache_info.identity_digest);
    smartlist_add(cl->certs, cert);
    if (ds && cert->cache_info.published_on > ds->addr_current_at) {
      /* Check to see whether we should update our view of the authority's
       * address. */
      if (cert->addr && cert->dir_port &&
          (ds->addr != cert->addr ||
           ds->dir_port != cert->dir_port)) {
        char *a = tor_dup_ip(cert->addr);
        log_notice(LD_DIR, "Updating address for directory authority %s "
                   "from %s:%d to %s:%d based on certificate.",
                   ds->nickname, ds->address, (int)ds->dir_port,
                   a, cert->dir_port);
        tor_free(a);
        ds->addr = cert->addr;
        ds->dir_port = cert->dir_port;
      }
      ds->addr_current_at = cert->cache_info.published_on;
    }

    if (!from_store)
      trusted_dir_servers_certs_changed = 1;
  }

  if (flush)
    trusted_dirs_flush_certs_to_disk();

  /* call this even if failure_code is <0, since some certs might have
   * succeeded. */
  networkstatus_note_certs_arrived();

  return failure_code;
}

/** Save all v3 key certificates to the cached-certs file. */
void
trusted_dirs_flush_certs_to_disk(void)
{
  char *filename;
  smartlist_t *chunks;

  if (!trusted_dir_servers_certs_changed || !trusted_dir_certs)
    return;

  chunks = smartlist_new();
  DIGESTMAP_FOREACH(trusted_dir_certs, key, cert_list_t *, cl) {
    SMARTLIST_FOREACH(cl->certs, authority_cert_t *, cert,
          {
            sized_chunk_t *c = tor_malloc(sizeof(sized_chunk_t));
            c->bytes = cert->cache_info.signed_descriptor_body;
            c->len = cert->cache_info.signed_descriptor_len;
            smartlist_add(chunks, c);
          });
  } DIGESTMAP_FOREACH_END;

  filename = get_datadir_fname("cached-certs");
  if (write_chunks_to_file(filename, chunks, 0, 0)) {
    log_warn(LD_FS, "Error writing certificates to disk.");
  }
  tor_free(filename);
  SMARTLIST_FOREACH(chunks, sized_chunk_t *, c, tor_free(c));
  smartlist_free(chunks);

  trusted_dir_servers_certs_changed = 0;
}

/** Remove all v3 authority certificates that have been superseded for more
 * than 48 hours.  (If the most recent cert was published more than 48 hours
 * ago, then we aren't going to get any consensuses signed with older
 * keys.) */
static void
trusted_dirs_remove_old_certs(void)
{
  time_t now = time(NULL);
#define DEAD_CERT_LIFETIME (2*24*60*60)
#define OLD_CERT_LIFETIME (7*24*60*60)
  