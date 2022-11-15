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
  if (!trusted_dir_certs)
    return;

  DIGESTMAP_FOREACH(trusted_dir_certs, key, cert_list_t *, cl) {
    authority_cert_t *newest = NULL;
    SMARTLIST_FOREACH(cl->certs, authority_cert_t *, cert,
          if (!newest || (cert->cache_info.published_on >
                          newest->cache_info.published_on))
            newest = cert);
    if (newest) {
      const time_t newest_published = newest->cache_info.published_on;
      SMARTLIST_FOREACH_BEGIN(cl->certs, authority_cert_t *, cert) {
        int expired;
        time_t cert_published;
        if (newest == cert)
          continue;
        expired = now > cert->expires;
        cert_published = cert->cache_info.published_on;
        /* Store expired certs for 48 hours after a newer arrives;
         */
        if (expired ?
            (newest_published + DEAD_CERT_LIFETIME < now) :
            (cert_published + OLD_CERT_LIFETIME < newest_published)) {
          SMARTLIST_DEL_CURRENT(cl->certs, cert);
          authority_cert_free(cert);
          trusted_dir_servers_certs_changed = 1;
        }
      } SMARTLIST_FOREACH_END(cert);
    }
  } DIGESTMAP_FOREACH_END;
#undef OLD_CERT_LIFETIME

  trusted_dirs_flush_certs_to_disk();
}

/** Return the newest v3 authority certificate whose v3 authority identity key
 * has digest <b>id_digest</b>.  Return NULL if no such authority is known,
 * or it has no certificate. */
authority_cert_t *
authority_cert_get_newest_by_id(const char *id_digest)
{
  cert_list_t *cl;
  authority_cert_t *best = NULL;
  if (!trusted_dir_certs ||
      !(cl = digestmap_get(trusted_dir_certs, id_digest)))
    return NULL;

  SMARTLIST_FOREACH(cl->certs, authority_cert_t *, cert,
  {
    if (!best || cert->cache_info.published_on > best->cache_info.published_on)
      best = cert;
  });
  return best;
}

/** Return the newest v3 authority certificate whose directory signing key has
 * digest <b>sk_digest</b>. Return NULL if no such certificate is known.
 */
authority_cert_t *
authority_cert_get_by_sk_digest(const char *sk_digest)
{
  authority_cert_t *c;
  if (!trusted_dir_certs)
    return NULL;

  if ((c = get_my_v3_authority_cert()) &&
      tor_memeq(c->signing_key_digest, sk_digest, DIGEST_LEN))
    return c;
  if ((c = get_my_v3_legacy_cert()) &&
      tor_memeq(c->signing_key_digest, sk_digest, DIGEST_LEN))
    return c;

  DIGESTMAP_FOREACH(trusted_dir_certs, key, cert_list_t *, cl) {
    SMARTLIST_FOREACH(cl->certs, authority_cert_t *, cert,
    {
      if (tor_memeq(cert->signing_key_digest, sk_digest, DIGEST_LEN))
        return cert;
    });
  } DIGESTMAP_FOREACH_END;
  return NULL;
}

/** Return the v3 authority certificate with signing key matching
 * <b>sk_digest</b>, for the authority with identity digest <b>id_digest</b>.
 * Return NULL if no such authority is known. */
authority_cert_t *
authority_cert_get_by_digests(const char *id_digest,
                              const char *sk_digest)
{
  cert_list_t *cl;
  if (!trusted_dir_certs ||
      !(cl = digestmap_get(trusted_dir_certs, id_digest)))
    return NULL;
  SMARTLIST_FOREACH(cl->certs, authority_cert_t *, cert,
    if (tor_memeq(cert->signing_key_digest, sk_digest, DIGEST_LEN))
      return cert; );

  return NULL;
}

/** Add every known authority_cert_t to <b>certs_out</b>. */
void
authority_cert_get_all(smartlist_t *certs_out)
{
  tor_assert(certs_out);
  if (!trusted_dir_certs)
    return;

  DIGESTMAP_FOREACH(trusted_dir_certs, key, cert_list_t *, cl) {
    SMARTLIST_FOREACH(cl->certs, authority_cert_t *, c,
                      smartlist_add(certs_out, c));
  } DIGESTMAP_FOREACH_END;
}

/** Called when an attempt to download a certificate with the authority with
 * ID <b>id_digest</b> and, if not NULL, signed with key signing_key_digest
 * fails with HTTP response code <b>status</b>: remember the failure, so we
 * don't try again immediately. */
void
authority_cert_dl_failed(const char *id_digest,
                         const char *signing_key_digest, int status)
{
  cert_list_t *cl;
  download_status_t *dlstatus = NULL;
  char id_digest_str[2*DIGEST_LEN+1];
  char sk_digest_str[2*DIGEST_LEN+1];

  if (!trusted_dir_certs ||
      !(cl = digestmap_get(trusted_dir_certs, id_digest)))
    return;

  /*
   * Are we noting a failed download of the latest cert for the id digest,
   * or of a download by (id, signing key) digest pair?
   */
  if (!signing_key_digest) {
    /* Just by id digest */
    download_status_failed(&cl->dl_status_by_id, status);
  } else {
    /* Reset by (id, signing key) digest pair
     *
     * Look for a download_status_t in the map with this digest
     */
    dlstatus = dsmap_get(cl->dl_status_map, signing_key_digest);
    /* Got one? */
    if (dlstatus) {
      download_status_failed(dlstatus, status);
    } else {
      /*
       * Do this rather than hex_str(), since hex_str clobbers
       * old results and we call twice in the param list.
       */
      base16_encode(id_digest_str, sizeof(id_digest_str),
                    id_digest, DIGEST_LEN);
      base16_encode(sk_digest_str, sizeof(sk_digest_str),
                    signing_key_digest, DIGEST_LEN);
      log_warn(LD_BUG,
               "Got failure for cert fetch with (fp,sk) = (%s,%s), with "
               "status %d, but knew nothing about the download.",
               id_digest_str, sk_digest_str, status);
    }
  }
}

/** Return true iff when we've been getting enough failures when trying to
 * download the certificate with ID digest <b>id_digest</b> that we're willing
 * to start bugging the user about it. */
int
authority_cert_dl_looks_uncertain(const char *id_digest)
{
#define N_AUTH_CERT_DL_FAILURES_TO_BUG_USER 2
  cert_list_t *cl;
  int n_failures;
  if (!trusted_dir_certs ||
      !(cl = digestmap_get(trusted_dir_certs, id_digest)))
    return 0;

  n_failures = download_status_get_n_failures(&cl->dl_status_by_id);
  return n_failures >= N_AUTH_CERT_DL_FAILURES_TO_BUG_USER;
}

/** Try to download any v3 authority certificates that we may be missing.  If
 * <b>status</b> is provided, try to get all the ones that were used to sign
 * <b>status</b>.  Additionally, try to have a non-expired certificate for
 * every V3 authority in trusted_dir_servers.  Don't fetch certificates we
 * already have.
 **/
void
authority_certs_fetch_missing(networkstatus_t *status, time_t now)
{
  /*
   * The pending_id digestmap tracks pending certificate downloads by
   * identity digest; the pending_cert digestmap tracks pending downloads
   * by (identity digest, signing key digest) pairs.
   */
  digestmap_t *pending_id;
  fp_pair_map_t *pending_cert;
  authority_cert_t *cert;
  /*
   * The missing_id_digests smartlist will hold a list of id digests
   * we want to fetch the newest cert for; the missing_cert_digests
   * smartlist will hold a list of fp_pair_t with an identity and
   * signing key digest.
   */
  smartlist_t *missing_cert_digests, *missing_id_digests;
  char *resource = NULL;
  cert_list_t *cl;
  const int cache = directory_caches_unknown_auth_certs(get_options());
  fp_pair_t *fp_tmp = NULL;
  char id_digest_str[2*DIGEST_LEN+1];
  char sk_digest_str[2*DIGEST_LEN+1];

  if (should_delay_dir_fetches(get_options()))
    return;

  pending_cert = fp_pair_map_new();
  pending_id = digestmap_new();
  missing_cert_digests = smartlist_new();
  missing_id_digests = smartlist_new();

  /*
   * First, we get the lists of already pending downloads so we don't
   * duplicate effort.
   */
  list_pending_downloads(pending_id, DIR_PURPOSE_FETCH_CERTIFICATE, "fp/");
  list_pending_fpsk_downloads(pending_cert);

  /*
   * Now, we download any trusted authority certs we don't have by
   * identity digest only.  This gets the latest cert for that authority.
   */
  SMARTLIST_FOREACH_BEGIN(trusted_dir_servers, dir_server_t *, ds) {
    int found = 0;
    if (!(ds->type & V3_DIRINFO))
      continue;
    if (smartlist_contains_digest(missing_id_digests,
                                  ds->v3_identity_digest))
      continue;
    cl = get_cert_list(ds->v3_identity_digest);
    SMARTLIST_FOREACH_BEGIN(cl->certs, authority_cert_t *, cert) {
      if (now < cert->expires) {
        /* It's not expired, and we weren't looking for something to
         * verify a consensus with.  Call it done. */
        download_status_reset(&(cl->dl_status_by_id));
        /* No sense trying to download it specifically by signing key hash */
        download_status_reset_by_sk_in_cl(cl, cert->signing_key_digest);
        found = 1;
        break;
      }
    } SMARTLIST_FOREACH_END(cert);
    if (!found &&
        download_status_is_ready(&(cl->dl_status_by_id), now,
                                 get_options()->TestingCertMaxDownloadTries) &&
        !digestmap_get(pending_id, ds->v3_identity_digest)) {
      log_info(LD_DIR,
               "No current certificate known for authority %s "
               "(ID digest %s); launching request.",
               ds->nickname, hex_str(ds->v3_identity_digest, DIGEST_LEN));
      smartlist_add(missing_id_digests, ds->v3_identity_digest);
    }
  } SMARTLIST_FOREACH_END(ds);

  /*
   * Next, if we have a consensus, scan through it and look for anything
   * signed with a key from a cert we don't have.  Those get downloaded
   * by (fp,sk) pair, but if we don't know any certs at all for the fp
   * (identity digest), and it's one of the trusted dir server certs
   * we started off above or a pending download in pending_id, don't
   * try to get it yet.  Most likely, the one we'll get for that will
   * have the right signing key too, and we'd just be downloading
   * redundantly.
   */
  if (status) {
    SMARTLIST_FOREACH_BEGIN(status->voters, networkstatus_voter_info_t *,
                            voter) {
      if (!smartlist_len(voter->sigs))
        continue; /* This authority never signed this consensus, so don't
                   * go looking for a cert with key digest 0000000000. */
      if (!cache &&
          !trusteddirserver_get_by_v3_auth_digest(voter->identity_digest))
        continue; /* We are not a cache, and we don't know this authority.*/

      /*
       * If we don't know *any* cert for this authority, and a download by ID
       * is pending or we added it to missing_id_digests above, skip this
       * one for now to avoid duplicate downloads.
       */
      cl = get_cert_list(voter->identity_digest);
      if (smartlist_len(cl->certs) == 0) {
        /* We have no certs at all for this one */

        /* Do we have a download of one pending? */
        if (digestmap_get(pending_id, voter->identity_digest))
          continue;

        /*
         * Are we about to launch a download of one due to the trusted
         * dir server check above?
         */
        if (smartlist_contains_digest(missing_id_digests,
                                      voter->identity_digest))
          continue;
      }

      SMARTLIST_FOREACH_BEGIN(voter->sigs, document_signature_t *, sig) {
        cert = authority_cert_get_by_digests(voter->identity_digest,
                                             sig->signing_key_digest);
        if (cert) {
          if (now < cert->expires)
            download_status_reset_by_sk_in_cl(cl, sig->signing_key_digest);
          continue;
        }
        if (download_status_is_ready_by_sk_in_cl(
              cl, sig->signing_key_digest,
              now, get_options()->TestingCertMaxDownloadTries) &&
            !fp_pair_map_get_by_digests(pending_cert,
                                        voter->identity_digest,
                                        sig->signing_key_digest)) {
          /*
           * Do this rather than hex_str(), since hex_str clobbers
           * old results and we call twice in the param list.
           */
          base16_encode(id_digest_str, sizeof(id_digest_str),
                        voter->identity_digest, DIGEST_LEN);
          base16_encode(sk_digest_str, sizeof(sk_digest_str),
                        sig->signing_key_digest, DIGEST_LEN);

          if (voter->nickname) {
            log_info(LD_DIR,
                     "We're missing a certificate from authority %s "
                     "(ID digest %s) with signing key %s: "
                     "launching request.",
                     voter->nickname, id_digest_str, sk_digest_str);
          } else {
            log_info(LD_DIR,
                     "We're missing a certificate from authority ID digest "
                     "%s with signing key %s: launching request.",
                     id_digest_str, sk_digest_str);
          }

          /* Allocate a new fp_pair_t to append */
          fp_tmp = tor_malloc(sizeof(*fp_tmp));
          memcpy(fp_tmp->first, voter->identity_digest, sizeof(fp_tmp->first));
          memcpy(fp_tmp->second, sig->signing_key_digest,
                 sizeof(fp_tmp->second));
          smartlist_add(missing_cert_digests, fp_tmp);
        }
      } SMARTLIST_FOREACH_END(sig);
    } SMARTLIST_FOREACH_END(voter);
  }

  /* Do downloads by identity digest */
  if (smartlist_len(missing_id_digests) > 0) {
    int need_plus = 0;
    smartlist_t *fps = smartlist_new();

    smartlist_add(fps, tor_strdup("fp/"));

    SMARTLIST_FOREACH_BEGIN(missing_id_digests, const char *, d) {
      char *fp = NULL;

      if (digestmap_get(pending_id, d))
        continue;

      base16_encode(id_digest_str, sizeof(id_digest_str),
                    d, DIGEST_LEN);

      if (need_plus) {
        tor_asprintf(&fp, "+%s", id_digest_str);
      } else {
        /* No need for tor_asprintf() in this case; first one gets no '+' */
        fp = tor_strdup(id_digest_str);
        need_plus = 1;
      }

      smartlist_add(fps, fp);
    } SMARTLIST_FOREACH_END(d);

    if (smartlist_len(fps) > 1) {
      resource = smartlist_join_strings(fps, "", 0, NULL);
      directory_get_from_dirserver(DIR_PURPOSE_FETCH_CERTIFICATE, 0,
                                   resource, PDS_RETRY_IF_NO_SERVERS);
      tor_free(resource);
    }
    /* else we didn't add any: they were all pending */

    SMARTLIST_FOREACH(fps, char *, cp, tor_free(cp));
    smartlist_free(fps);
  }

  /* Do downloads by identity digest/signing key pair */
  if (smartlist_len(missing_cert_digests) > 0) {
    int need_plus = 0;
    smartlist_t *fp_pairs = smartlist_new();

    smartlist_add(fp_pairs, tor_strdup("fp-sk/"));

    SMARTLIST_FOREACH_BEGIN(missing_cert_digests, const fp_pair_t *, d) {
      char *fp_pair = NULL;

      if (fp_pair_map_get(pending_cert, d))
        continue;

      /* Construct string encodings of the digests */
      base16_encode(id_digest_str, sizeof(id_digest_str),
                    d->first, DIGEST_LEN);
      base16_encode(sk_digest_str, sizeof(sk_digest_str),
                    d->second, DIGEST_LEN);

      /* Now tor_asprintf() */
      if (need_plus) {
        tor_asprintf(&fp_pair, "+%s-%s", id_digest_str, sk_digest_str);
      } else {
        /* First one in the list doesn't get a '+' */
        tor_asprintf(&fp_pair, "%s-%s", id_digest_str, sk_digest_str);
        need_plus = 1;
      }

      /* Add it to the list of pairs to request */
      smartlist_add(fp_pairs, fp_pair);
    } SMARTLIST_FOREACH_END(d);

    if (smartlist_len(fp_pairs) > 1) {
      resource = smartlist_join_strings(fp_pairs, "", 0, NULL);
      directory_get_from_dirserver(DIR_PURPOSE_FETCH_CERTIFICATE, 0,
                                   resource, PDS_RETRY_IF_NO_SERVERS);
      tor_free(resource);
    }
    /* else they were all pending */

    SMARTLIST_FOREACH(fp_pairs, char *, p, tor_free(p));
    smartlist_free(fp_pairs);
  }

  smartlist_free(missing_id_digests);
  SMARTLIST_FOREACH(missing_cert_digests, fp_pair_t *, p, tor_free(p));
  smartlist_free(missing_cert_digests);
  digestmap_free(pending_id, NULL);
  fp_pair_map_free(pending_cert, NULL);
}

/* Router descriptor storage.
 *
 * Routerdescs are stored in a big file, named "cached-descriptors".  As new
 * routerdescs arrive, we append them to a journal file named
 * "cached-descriptors.new".
 *
 * From time to time, we replace "cached-descriptors" with a new file
 * containing only the live, non-superseded descriptors, and clear
 * cached-routers.new.
 *
 * On startup, we read both files.
 */

/** Helper: return 1 iff the router log is so big we want to rebuild the
 * store. */
static int
router_should_rebuild_store(desc_store_t *store)
{
  if (store->store_len > (1<<16))
    return (store->journal_len > store->store_len / 2 ||
            store->bytes_dropped > store->store_len / 2);
  else
    return store->journal_len > (1<<15);
}

/** Return the desc_store_t in <b>rl</b> that should be used to store
 * <b>sd</b>. */
static INLINE desc_store_t *
desc_get_store(routerlist_t *rl, const signed_descriptor_t *sd)
{
  if (sd->is_extrainfo)
    return &rl->extrainfo_store;
  else
    return &rl->desc_store;
}

/** Add the signed_descriptor_t in <b>desc</b> to the router
 * journal; change its saved_location to SAVED_IN_JOURNAL and set its
 * offset appropriately. */
static int
signed_desc_append_to_journal(signed_descriptor_t *desc,
                              desc_store_t *store)
{
  char *fname = get_datadir_fname_suffix(store->fname_base, ".new");
  const char *body = signed_descriptor_get_body_impl(desc,1);
  size_t len = desc->signed_descriptor_len + desc->annotations_len;

  if (append_bytes_to_file(fname, body, len, 1)) {
    log_warn(LD_FS, "Unable to store router descriptor");
    tor_free(fname);
    return -1;
  }
  desc->saved_location = SAVED_IN_JOURNAL;
  tor_free(fname);

  desc->saved_offset = store->journal_len;
  store->journal_len += len;

  return 0;
}

/** Sorting helper: return &lt;0, 0, or &gt;0 depending on whether the
 * signed_descriptor_t* in *<b>a</b> is older, the same age as, or newer than
 * the signed_descriptor_t* in *<b>b</b>. */
static int
compare_signed_descriptors_by_age_(const void **_a, const void **_b)
{
  const signed_descriptor_t *r1 = *_a, *r2 = *_b;
  return (int)(r1->published_on - r2->published_on);
}

#define RRS_FORCE 1
#define RRS_DONT_REMOVE_OLD 2

/** If the journal of <b>store</b> is too long, or if RRS_FORCE is set in
 * <b>flags</b>, then atomically replace the saved router store with the
 * routers currently in our routerlist, and clear the journal.  Unless
 * RRS_DONT_REMOVE_OLD is set in <b>flags</b>, delete expired routers before
 * rebuilding the store.  Return 0 on success, -1 on failure.
 */
static int
router_rebuild_store(int flags, desc_store_t *store)
{
  smartlist_t *chunk_list = NULL;
  char *fname = NULL, *fname_tmp = NULL;
  int r = -1;
  off_t offset = 0;
  smartlist_t *signed_descriptors = NULL;
  int nocache=0;
  size_t total_expected_len = 0;
  int had_any;
  int force = flags & RRS_FORCE;

  if (!force && !router_should_rebuild_store(store)) {
    r = 0;
    goto done;
  }
  if (!routerlist) {
    r = 0;
    goto done;
  }

  if (store->type == EXTRAINFO_STORE)
    had_any = !eimap_isempty(routerlist->extra_info_map);
  else
    had_any = (smartlist_len(routerlist->routers)+
               smartlist_len(routerlist->old_routers))>0;

  /* Don't save deadweight. */
  if (!(flags & RRS_DONT_REMOVE_OLD))
    routerlist_remove_old_routers();

  log_info(LD_DIR, "Rebuilding %s cache", store->description);

  fname = get_datadir_fname(store->fname_base);
  fname_tmp = get_datadir_fname_suffix(store->fname_base, ".tmp");

  chunk_list = smartlist_new();

  /* We sort the routers by age to enhance locality on disk. */
  signed