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
  signed_descriptors = smartlist_new();
  if (store->type == EXTRAINFO_STORE) {
    eimap_iter_t *iter;
    for (iter = eimap_iter_init(routerlist->extra_info_map);
         !eimap_iter_done(iter);
         iter = eimap_iter_next(routerlist->extra_info_map, iter)) {
      const char *key;
      extrainfo_t *ei;
      eimap_iter_get(iter, &key, &ei);
      smartlist_add(signed_descriptors, &ei->cache_info);
    }
  } else {
    SMARTLIST_FOREACH(routerlist->old_routers, signed_descriptor_t *, sd,
                      smartlist_add(signed_descriptors, sd));
    SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, ri,
                      smartlist_add(signed_descriptors, &ri->cache_info));
  }

  smartlist_sort(signed_descriptors, compare_signed_descriptors_by_age_);

  /* Now, add the appropriate members to chunk_list */
  SMARTLIST_FOREACH_BEGIN(signed_descriptors, signed_descriptor_t *, sd) {
      sized_chunk_t *c;
      const char *body = signed_descriptor_get_body_impl(sd, 1);
      if (!body) {
        log_warn(LD_BUG, "No descriptor available for router.");
        goto done;
      }
      if (sd->do_not_cache) {
        ++nocache;
        continue;
      }
      c = tor_malloc(sizeof(sized_chunk_t));
      c->bytes = body;
      c->len = sd->signed_descriptor_len + sd->annotations_len;
      total_expected_len += c->len;
      smartlist_add(chunk_list, c);
  } SMARTLIST_FOREACH_END(sd);

  if (write_chunks_to_file(fname_tmp, chunk_list, 1, 1)<0) {
    log_warn(LD_FS, "Error writing router store to disk.");
    goto done;
  }

  /* Our mmap is now invalid. */
  if (store->mmap) {
    tor_munmap_file(store->mmap);
    store->mmap = NULL;
  }

  if (replace_file(fname_tmp, fname)<0) {
    log_warn(LD_FS, "Error replacing old router store: %s", strerror(errno));
    goto done;
  }

  errno = 0;
  store->mmap = tor_mmap_file(fname);
  if (! store->mmap) {
    if (errno == ERANGE) {
      /* empty store.*/
      if (total_expected_len) {
        log_warn(LD_FS, "We wrote some bytes to a new descriptor file at '%s',"
                 " but when we went to mmap it, it was empty!", fname);
      } else if (had_any) {
        log_info(LD_FS, "We just removed every descriptor in '%s'.  This is "
                 "okay if we're just starting up after a long time. "
                 "Otherwise, it's a bug.", fname);
      }
    } else {
      log_warn(LD_FS, "Unable to mmap new descriptor file at '%s'.",fname);
    }
  }

  log_info(LD_DIR, "Reconstructing pointers into cache");

  offset = 0;
  SMARTLIST_FOREACH_BEGIN(signed_descriptors, signed_descriptor_t *, sd) {
      if (sd->do_not_cache)
        continue;
      sd->saved_location = SAVED_IN_CACHE;
      if (store->mmap) {
        tor_free(sd->signed_descriptor_body); // sets it to null
        sd->saved_offset = offset;
      }
      offset += sd->signed_descriptor_len + sd->annotations_len;
      signed_descriptor_get_body(sd); /* reconstruct and assert */
  } SMARTLIST_FOREACH_END(sd);

  tor_free(fname);
  fname = get_datadir_fname_suffix(store->fname_base, ".new");
  write_str_to_file(fname, "", 1);

  r = 0;
  store->store_len = (size_t) offset;
  store->journal_len = 0;
  store->bytes_dropped = 0;
 done:
  smartlist_free(signed_descriptors);
  tor_free(fname);
  tor_free(fname_tmp);
  if (chunk_list) {
    SMARTLIST_FOREACH(chunk_list, sized_chunk_t *, c, tor_free(c));
    smartlist_free(chunk_list);
  }

  return r;
}

/** Helper: Reload a cache file and its associated journal, setting metadata
 * appropriately.  If <b>extrainfo</b> is true, reload the extrainfo store;
 * else reload the router descriptor store. */
static int
router_reload_router_list_impl(desc_store_t *store)
{
  char *fname = NULL, *contents = NULL;
  struct stat st;
  int extrainfo = (store->type == EXTRAINFO_STORE);
  store->journal_len = store->store_len = 0;

  fname = get_datadir_fname(store->fname_base);

  if (store->mmap) /* get rid of it first */
    tor_munmap_file(store->mmap);
  store->mmap = NULL;

  store->mmap = tor_mmap_file(fname);
  if (store->mmap) {
    store->store_len = store->mmap->size;
    if (extrainfo)
      router_load_extrainfo_from_string(store->mmap->data,
                                        store->mmap->data+store->mmap->size,
                                        SAVED_IN_CACHE, NULL, 0);
    else
      router_load_routers_from_string(store->mmap->data,
                                      store->mmap->data+store->mmap->size,
                                      SAVED_IN_CACHE, NULL, 0, NULL);
  }

  tor_free(fname);
  fname = get_datadir_fname_suffix(store->fname_base, ".new");
  if (file_status(fname) == FN_FILE)
    contents = read_file_to_str(fname, RFTS_BIN|RFTS_IGNORE_MISSING, &st);
  if (contents) {
    if (extrainfo)
      router_load_extrainfo_from_string(contents, NULL,SAVED_IN_JOURNAL,
                                        NULL, 0);
    else
      router_load_routers_from_string(contents, NULL, SAVED_IN_JOURNAL,
                                      NULL, 0, NULL);
    store->journal_len = (size_t) st.st_size;
    tor_free(contents);
  }

  tor_free(fname);

  if (store->journal_len) {
    /* Always clear the journal on startup.*/
    router_rebuild_store(RRS_FORCE, store);
  } else if (!extrainfo) {
    /* Don't cache expired routers. (This is in an else because
     * router_rebuild_store() also calls remove_old_routers().) */
    routerlist_remove_old_routers();
  }

  return 0;
}

/** Load all cached router descriptors and extra-info documents from the
 * store. Return 0 on success and -1 on failure.
 */
int
router_reload_router_list(void)
{
  routerlist_t *rl = router_get_routerlist();
  if (router_reload_router_list_impl(&rl->desc_store))
    return -1;
  if (router_reload_router_list_impl(&rl->extrainfo_store))
    return -1;
  return 0;
}

/** Return a smartlist containing a list of dir_server_t * for all
 * known trusted dirservers.  Callers must not modify the list or its
 * contents.
 */
const smartlist_t *
router_get_trusted_dir_servers(void)
{
  if (!trusted_dir_servers)
    trusted_dir_servers = smartlist_new();

  return trusted_dir_servers;
}

const smartlist_t *
router_get_fallback_dir_servers(void)
{
  if (!fallback_dir_servers)
    fallback_dir_servers = smartlist_new();

  return fallback_dir_servers;
}

/** Try to find a running dirserver that supports operations of <b>type</b>.
 *
 * If there are no running dirservers in our routerlist and the
 * <b>PDS_RETRY_IF_NO_SERVERS</b> flag is set, set all the authoritative ones
 * as running again, and pick one.
 *
 * If the <b>PDS_IGNORE_FASCISTFIREWALL</b> flag is set, then include
 * dirservers that we can't reach.
 *
 * If the <b>PDS_ALLOW_SELF</b> flag is not set, then don't include ourself
 * (if we're a dirserver).
 *
 * Don't pick an authority if any non-authority is viable; try to avoid using
 * servers that have returned 503 recently.
 */
const routerstatus_t *
router_pick_directory_server(dirinfo_type_t type, int flags)
{
  const routerstatus_t *choice;
  if (get_options()->PreferTunneledDirConns)
    flags |= PDS_PREFER_TUNNELED_DIR_CONNS_;

  if (!routerlist)
    return NULL;

  choice = router_pick_directory_server_impl(type, flags);
  if (choice || !(flags & PDS_RETRY_IF_NO_SERVERS))
    return choice;

  log_info(LD_DIR,
           "No reachable router entries for dirservers. "
           "Trying them all again.");
  /* mark all authdirservers as up again */
  mark_all_dirservers_up(fallback_dir_servers);
  /* try again */
  choice = router_pick_directory_server_impl(type, flags);
  return choice;
}

/** Try to determine which fraction ofv3 directory requests aimed at
 * caches will be sent to us. Set
 * *<b>v3_share_out</b> to the fraction of v3 protocol shares we
 * expect to see.  Return 0 on success, negative on failure. */
/* XXXX This function is unused. */
int
router_get_my_share_of_directory_requests(double *v3_share_out)
{
  const routerinfo_t *me = router_get_my_routerinfo();
  const routerstatus_t *rs;
  const int pds_flags = PDS_ALLOW_SELF|PDS_IGNORE_FASCISTFIREWALL;
  *v3_share_out = 0.0;
  if (!me)
    return -1;
  rs = router_get_consensus_status_by_id(me->cache_info.identity_digest);
  if (!rs)
    return -1;

  /* Calling for side effect */
  /* XXXX This is a bit of a kludge */
  {
    sl_last_total_weighted_bw = 0;
    router_pick_directory_server(V3_DIRINFO, pds_flags);
    if (sl_last_total_weighted_bw != 0) {
      *v3_share_out = U64_TO_DBL(sl_last_weighted_bw_of_me) /
        U64_TO_DBL(sl_last_total_weighted_bw);
    }
  }

  return 0;
}

/** Return the dir_server_t for the directory authority whose identity
 * key hashes to <b>digest</b>, or NULL if no such authority is known.
 */
dir_server_t *
router_get_trusteddirserver_by_digest(const char *digest)
{
  if (!trusted_dir_servers)
    return NULL;

  SMARTLIST_FOREACH(trusted_dir_servers, dir_server_t *, ds,
     {
       if (tor_memeq(ds->digest, digest, DIGEST_LEN))
         return ds;
     });

  return NULL;
}

/** Return the dir_server_t for the fallback dirserver whose identity
 * key hashes to <b>digest</b>, or NULL if no such authority is known.
 */
dir_server_t *
router_get_fallback_dirserver_by_digest(const char *digest)
{
  if (!trusted_dir_servers)
    return NULL;

  SMARTLIST_FOREACH(trusted_dir_servers, dir_server_t *, ds,
     {
       if (tor_memeq(ds->digest, digest, DIGEST_LEN))
         return ds;
     });

  return NULL;
}

/** Return the dir_server_t for the directory authority whose
 * v3 identity key hashes to <b>digest</b>, or NULL if no such authority
 * is known.
 */
dir_server_t *
trusteddirserver_get_by_v3_auth_digest(const char *digest)
{
  if (!trusted_dir_servers)
    return NULL;

  SMARTLIST_FOREACH(trusted_dir_servers, dir_server_t *, ds,
     {
       if (tor_memeq(ds->v3_identity_digest, digest, DIGEST_LEN) &&
           (ds->type & V3_DIRINFO))
         return ds;
     });

  return NULL;
}

/** Try to find a running directory authority. Flags are as for
 * router_pick_directory_server.
 */
const routerstatus_t *
router_pick_trusteddirserver(dirinfo_type_t type, int flags)
{
  return router_pick_dirserver_generic(trusted_dir_servers, type, flags);
}

/** Try to find a running fallback directory Flags are as for
 * router_pick_directory_server.
 */
const routerstatus_t *
router_pick_fallback_dirserver(dirinfo_type_t type, int flags)
{
  return router_pick_dirserver_generic(fallback_dir_servers, type, flags);
}

/** Try to find a running fallback directory Flags are as for
 * router_pick_directory_server.
 */
static const routerstatus_t *
router_pick_dirserver_generic(smartlist_t *sourcelist,
                              dirinfo_type_t type, int flags)
{
  const routerstatus_t *choice;
  int busy = 0;
  if (get_options()->PreferTunneledDirConns)
    flags |= PDS_PREFER_TUNNELED_DIR_CONNS_;

  choice = router_pick_trusteddirserver_impl(sourcelist, type, flags, &busy);
  if (choice || !(flags & PDS_RETRY_IF_NO_SERVERS))
    return choice;
  if (busy) {
    /* If the reason that we got no server is that servers are "busy",
     * we must be excluding good servers because we already have serverdesc
     * fetches with them.  Do not mark down servers up because of this. */
    tor_assert((flags & (PDS_NO_EXISTING_SERVERDESC_FETCH|
                         PDS_NO_EXISTING_MICRODESC_FETCH)));
    return NULL;
  }

  log_info(LD_DIR,
           "No dirservers are reachable. Trying them all again.");
  mark_all_dirservers_up(sourcelist);
  return router_pick_trusteddirserver_impl(sourcelist, type, flags, NULL);
}

/** How long do we avoid using a directory server after it's given us a 503? */
#define DIR_503_TIMEOUT (60*60)

/** Pick a random running valid directory server/mirror from our
 * routerlist.  Arguments are as for router_pick_directory_server(), except
 * that RETRY_IF_NO_SERVERS is ignored, and:
 *
 * If the PDS_PREFER_TUNNELED_DIR_CONNS_ flag is set, prefer directory servers
 * that we can use with BEGINDIR.
 */
static const routerstatus_t *
router_pick_directory_server_impl(dirinfo_type_t type, int flags)
{
  const or_options_t *options = get_options();
  const node_t *result;
  smartlist_t *direct, *tunnel;
  smartlist_t *trusted_direct, *trusted_tunnel;
  smartlist_t *overloaded_direct, *overloaded_tunnel;
  time_t now = time(NULL);
  const networkstatus_t *consensus = networkstatus_get_latest_consensus();
  int requireother = ! (flags & PDS_ALLOW_SELF);
  int fascistfirewall = ! (flags & PDS_IGNORE_FASCISTFIREWALL);
  int prefer_tunnel = (flags & PDS_PREFER_TUNNELED_DIR_CONNS_);
  int for_guard = (flags & PDS_FOR_GUARD);
  int try_excluding = 1, n_excluded = 0;

  if (!consensus)
    return NULL;

 retry_without_exclude:

  direct = smartlist_new();
  tunnel = smartlist_new();
  trusted_direct = smartlist_new();
  trusted_tunnel = smartlist_new();
  overloaded_direct = smartlist_new();
  overloaded_tunnel = smartlist_new();

  /* Find all the running dirservers we know about. */
  SMARTLIST_FOREACH_BEGIN(nodelist_get_list(), const node_t *, node) {
    int is_trusted;
    int is_overloaded;
    tor_addr_t addr;
    const routerstatus_t *status = node->rs;
    const country_t country = node->country;
    if (!status)
      continue;

    if (!node->is_running || !status->dir_port || !node->is_valid)
      continue;
    if (node->is_bad_directory)
      continue;
    if (requireother && router_digest_is_me(node->identity))
      continue;
    is_trusted = router_digest_is_trusted_dir(node->identity);
    if ((type & EXTRAINFO_DIRINFO) &&
        !router_supports_extrainfo(node->identity, 0))
      continue;
    if ((type & MICRODESC_DIRINFO) && !is_trusted &&
        !node->rs->version_supports_microdesc_cache)
      continue;
    if (for_guard && node->using_as_guard)
      continue; /* Don't make the same node a guard twice. */
    if (try_excluding &&
        routerset_contains_routerstatus(options->ExcludeNodes, status,
                                        country)) {
      ++n_excluded;
      continue;
    }

    /* XXXX IP6 proposal 118 */
    tor_addr_from_ipv4h(&addr, node->rs->addr);

    is_overloaded = status->last_dir_503_at + DIR_503_TIMEOUT > now;

    if (prefer_tunnel &&
        (!fascistfirewall ||
         fascist_firewall_allows_address_or(&addr, status->or_port)))
      smartlist_add(is_trusted ? trusted_tunnel :
                    is_overloaded ? overloaded_tunnel : tunnel, (void*)node);
    else if (!fascistfirewall ||
             fascist_firewall_allows_address_dir(&addr, status->dir_port))
      smartlist_add(is_trusted ? trusted_direct :
                    is_overloaded ? overloaded_direct : direct, (void*)node);
  } SMARTLIST_FOREACH_END(node);

  if (smartlist_len(tunnel)) {
    result = node_sl_choose_by_bandwidth(tunnel, WEIGHT_FOR_DIR);
  } else if (smartlist_len(overloaded_tunnel)) {
    result = node_sl_choose_by_bandwidth(overloaded_tunnel,
                                                 WEIGHT_FOR_DIR);
  } else if (smartlist_len(trusted_tunnel)) {
    /* FFFF We don't distinguish between trusteds and overloaded trusteds
     * yet. Maybe one day we should. */
    /* FFFF We also don't load balance over authorities yet. I think this
     * is a feature, but it could easily be a bug. -RD */
    result = smartlist_choose(trusted_tunnel);
  } else if (smartlist_len(direct)) {
    result = node_sl_choose_by_bandwidth(direct, WEIGHT_FOR_DIR);
  } else if (smartlist_len(overloaded_direct)) {
    result = node_sl_choose_by_bandwidth(overloaded_direct,
                                         WEIGHT_FOR_DIR);
  } else {
    result = smartlist_choose(trusted_direct);
  }
  smartlist_free(direct);
  smartlist_free(tunnel);
  smartlist_free(trusted_direct);
  smartlist_free(trusted_tunnel);
  smartlist_free(overloaded_direct);
  smartlist_free(overloaded_tunnel);

  if (result == NULL && try_excluding && !options->StrictNodes && n_excluded) {
    /* If we got no result, and we are excluding nodes, and StrictNodes is
     * not set, try again without excluding nodes. */
    try_excluding = 0;
    n_excluded = 0;
    goto retry_without_exclude;
  }

  return result ? result->rs : NULL;
}

/** Pick a random element from a list of dir_server_t, weighting by their
 * <b>weight</b> field. */
static const dir_server_t *
dirserver_choose_by_weight(const smartlist_t *servers, double authority_weight)
{
  int n = smartlist_len(servers);
  int i;
  u64_dbl_t *weights;
  const dir_server_t *ds;

  weights = tor_malloc(sizeof(u64_dbl_t) * n);
  for (i = 0; i < n; ++i) {
    ds = smartlist_get(servers, i);
    weights[i].dbl = ds->weight;
    if (ds->is_authority)
      weights[i].dbl *= authority_weight;
  }

  scale_array_elements_to_u64(weights, n, NULL);
  i = choose_array_element_by_weight(weights, n);
  tor_free(weights);
  return (i < 0) ? NULL : smartlist_get(servers, i);
}

/** Choose randomly from among the dir_server_ts in sourcelist that
 * are up. Flags are as for router_pick_directory_server_impl().
 */
static const routerstatus_t *
router_pick_trusteddirserver_impl(const smartlist_t *sourcelist,
                                  dirinfo_type_t type, int flags,
                                  int *n_busy_out)
{
  const or_options_t *options = get_options();
  smartlist_t *direct, *tunnel;
  smartlist_t *overloaded_direct, *overloaded_tunnel;
  const routerinfo_t *me = router_get_my_routerinfo();
  const routerstatus_t *result = NULL;
  time_t now = time(NULL);
  const int requireother = ! (flags & PDS_ALLOW_SELF);
  const int fascistfirewall = ! (flags & PDS_IGNORE_FASCISTFIREWALL);
  const int prefer_tunnel = (flags & PDS_PREFER_TUNNELED_DIR_CONNS_);
  const int no_serverdesc_fetching =(flags & PDS_NO_EXISTING_SERVERDESC_FETCH);
  const int no_microdesc_fetching =(flags & PDS_NO_EXISTING_MICRODESC_FETCH);
  const double auth_weight = (sourcelist == fallback_dir_servers) ?
    options->DirAuthorityFallbackRate : 1.0;
  smartlist_t *pick_from;
  int n_busy = 0;
  int try_excluding = 1, n_excluded = 0;

  if (!sourcelist)
    return NULL;

 retry_without_exclude:

  direct = smartlist_new();
  tunnel = smartlist_new();
  overloaded_direct = smartlist_new();
  overloaded_tunnel = smartlist_new();

  SMARTLIST_FOREACH_BEGIN(sourcelist, const dir_server_t *, d)
    {
      int is_overloaded =
          d->fake_status.last_dir_503_at + DIR_503_TIMEOUT > now;
      tor_addr_t addr;
      if (!d->is_running) continue;
      if ((type & d->type) == 0)
        continue;
      if ((type & EXTRAINFO_DIRINFO) &&
          !router_supports_extrainfo(d->digest, 1))
        continue;
      if (requireother && me && router_digest_is_me(d->digest))
          continue;
      if (try_excluding &&
          routerset_contains_routerstatus(options->ExcludeNodes,
                                          &d->fake_status, -1)) {
        ++n_excluded;
        continue;
      }

      /* XXXX IP6 proposal 118 */
      tor_addr_from_ipv4h(&addr, d->addr);

      if (no_serverdesc_fetching) {
        if (connection_get_by_type_addr_port_purpose(
            CONN_TYPE_DIR, &addr, d->dir_port, DIR_PURPOSE_FETCH_SERVERDESC)
         || connection_get_by_type_addr_port_purpose(
             CONN_TYPE_DIR, &addr, d->dir_port, DIR_PURPOSE_FETCH_EXTRAINFO)) {
          //log_debug(LD_DIR, "We have an existing connection to fetch "
          //           "descriptor from %s; delaying",d->description);
          ++n_busy;
          continue;
        }
      }
      if (no_microdesc_fetching) {
        if (connection_get_by_type_addr_port_purpose(
             CONN_TYPE_DIR, &addr, d->dir_port, DIR_PURPOSE_FETCH_MICRODESC)) {
          ++n_busy;
          continue;
        }
      }

      if (prefer_tunnel &&
          d->or_port &&
          (!fascistfirewall ||
           fascist_firewall_allows_address_or(&addr, d->or_port)))
        smartlist_add(is_overloaded ? overloaded_tunnel : tunnel, (void*)d);
      else if (!fascistfirewall ||
               fascist_firewall_allows_address_dir(&addr, d->dir_port))
        smartlist_add(is_overloaded ? overloaded_direct : direct, (void*)d);
    }
  SMARTLIST_FOREACH_END(d);

  if (smartlist_len(tunnel)) {
    pick_from = tunnel;
  } else if (smartlist_len(overloaded_tunnel)) {
    pick_from = overloaded_tunnel;
  } else if (smartlist_len(direct)) {
    pick_from = direct;
  } else {
    pick_from = overloaded_direct;
  }

  {
    const dir_server_t *selection =
      dirserver_choose_by_weight(pick_from, auth_weight);

    if (selection)
      result = &selection->fake_status;
  }

  if (n_busy_out)
    *n_busy_out = n_busy;

  smartlist_free(direct);
  smartlist_free(tunnel);
  smartlist_free(overloaded_direct);
  smartlist_free(overloaded_tunnel);

  if (result == NULL && try_excluding && !options->StrictNodes && n_excluded) {
    /* If we got no result, and we are excluding nodes, and StrictNodes is
     * not set, try again without excluding nodes. */
    try_excluding = 0;
    n_excluded = 0;
    goto retry_without_exclude;
  }

  return result;
}

/** Mark as running every dir_server_t in <b>server_list</b>. */
static void
mark_all_dirservers_up(smartlist_t *server_list)
{
  if (server_list) {
    SMARTLIST_FOREACH_BEGIN(server_list, dir_server_t *, dir) {
      routerstatus_t *rs;
      node_t *node;
      dir->is_running = 1;
      node = node_get_mutable_by_id(dir->digest);
      if (node)
        node->is_running = 1;
      rs = router_get_mutable_consensus_status_by_id(dir->digest);
      if (rs) {
        rs->last_dir_503_at = 0;
        control_event_networkstatus_changed_single(rs);
      }
    } SMARTLIST_FOREACH_END(dir);
  }
  router_dir_info_changed();
}

/** Return true iff r1 and r2 have the same address and OR port. */
int
routers_have_same_or_addrs(const routerinfo_t *r1, const routerinfo_t *r2)
{
  return r1->addr == r2->addr && r1->or_port == r2->or_port &&
    tor_addr_eq(&r1->ipv6_addr, &r2->ipv6_addr) &&
    r1->ipv6_orport == r2->ipv6_orport;
}

/** Reset all internal variables used to count failed downloads of network
 * status objects. */
void
router_reset_status_download_failures(void)
{
  mark_all_dirservers_up(fallback_dir_servers);
}

/** Given a <b>router</b>, add every node_t in its family (including the
 * node itself!) to <b>sl</b>.
 *
 * Note the type mismatch: This function takes a routerinfo, but adds nodes
 * to the smartlist!
 */
static void
routerlist_add_node_and_family(smartlist_t *sl, const routerinfo_t *router)
{
  /* XXXX MOVE ? */
  node_t fake_node;
  const node_t *node = node_get_by_id(router->cache_info.identity_digest);;
  if (node == NULL) {
    memset(&fake_node, 0, sizeof(fake_node));
    fake_node.ri = (routerinfo_t *)router;
    memcpy(fake_node.identity, router->cache_info.identity_digest, DIGEST_LEN);
    node = &fake_node;
  }
  nodelist_add_node_and_family(sl, node);
}

/** Add every suitable node from our nodelist to <b>sl</b>, so that
 * we can pick a node for a circuit.
 */
static void
router_add_running_nodes_to_smartlist(smartlist_t *sl, int allow_invalid,
                                      int need_uptime, int need_capacity,
                                      int need_guard, int need_desc)
{ /* XXXX MOVE */
  SMARTLIST_FOREACH_BEGIN(nodelist_get_list(), const node_t *, node) {
    if (!node->is_running ||
        (!node->is_valid && !allow_invalid))
      continue;
    if (need_desc && !(node->ri || (node->rs && node->md)))
      continue;
    if (node->ri && node->ri->purpose != ROUTER_PURPOSE_GENERAL)
      continue;
    if (node_is_unreliable(node, need_uptime, need_capacity, need_guard))
      continue;

    smartlist_add(sl, (void *)node);
  } SMARTLIST_FOREACH_END(node);
}

/** Look through the routerlist until we find a router that has my key.
 Return it. */
const routerinfo_t *
routerlist_find_my_routerinfo(void)
{
  if (!routerlist)
    return NULL;

  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, router,
  {
    if (router_is_me(router))
      return router;
  });
  return NULL;
}

/** Return the smaller of the router's configured BandwidthRate
 * and its advertised capacity. */
uint32_t
router_get_advertised_bandwidth(const routerinfo_t *router)
{
  if (router->bandwidthcapacity < router->bandwidthrate)
    return router->bandwidthcapacity;
  return router->bandwidthrate;
}

/** Do not weight any declared bandwidth more than this much when picking
 * routers by bandwidth. */
#define DEFAULT_MAX_BELIEVABLE_BANDWIDTH 10000000 /* 10 MB/sec */

/** Return the smaller of the router's configured BandwidthRate
 * and its advertised capacity, capped by max-believe-bw. */
uint32_t
router_get_advertised_bandwidth_capped(const routerinfo_t *router)
{
  uint32_t result = router->bandwidthcapacity;
  if (result > router->bandwidthrate)
    result = router->bandwidthrate;
  if (result > DEFAULT_MAX_BELIEVABLE_BANDWIDTH)
    result = DEFAULT_MAX_BELIEVABLE_BANDWIDTH;
  return result;
}

/** Given an array of double/uint64_t unions that are currently being used as
 * doubles, convert them to uint64_t, and try to scale them linearly so as to
 * much of the range of uint64_t. If <b>total_out</b> is provided, set it to
 * the sum of all elements in the array _before_ scaling. */
STATIC void
scale_array_elements_to_u64(u64_dbl_t *entries, int n_entries,
                            uint64_t *total_out)
{
  double total = 0.0;
  double scale_factor;
  int i;
  /* big, but far away from overflowing an int64_t */
#define SCALE_TO_U64_MAX (INT64_MAX / 4)

  for (i = 0; i < n_entries; ++i)
    total += entries[i].dbl;

  scale_factor = SCALE_TO_U64_MAX / total;

  for (i = 0; i < n_entries; ++i)
    entries[i].u64 = tor_llround(entries[i].dbl * scale_factor);

  if (total_out)
    *total_out = (uint64_t) total;

#undef SCALE_TO_U64_MAX
}

/** Time-invariant 64-bit greater-than; works on two integers in the range
 * (0,INT64_MAX). */
#if SIZEOF_VOID_P == 8
#define gt_i64_timei(a,b) ((a) > (b))
#else
static INLINE int
gt_i64_timei(uint64_t a, uint64_t b)
{
  int64_t diff = (int64_t) (b - a);
  int res = diff >> 63;
  return res & 1;
}
#endif

/** Pick a random element of <b>n_entries</b>-element array <b>entries</b>,
 * choosing each element with a probability proportional to its (uint64_t)
 * value, and return the index of that element.  If all elements are 0, choose
 * an index at random. Return -1 on error.
 */
STATIC int
choose_array_element_by_weight(const u64_dbl_t *entries, int n_entries)
{
  int i, i_chosen=-1, n_chosen=0;
  uint64_t total_so_far = 0;
  uint64_t rand_val;
  uint64_t total = 0;

  for (i = 0; i < n_entries; ++i)
    total += entries[i].u64;

  if (n_entries < 1)
    return -1;

  if (total == 0)
    return crypto_rand_int(n_entries);

  tor_assert(total < INT64_MAX);

  rand_val = crypto_rand_uint64(total);

  for (i = 0; i < n_entries; ++i) {
    total_so_far += entries[i].u64;
    if (gt_i64_timei(total_so_far, rand_val)) {
      i_chosen = i;
      n_chosen++;
      /* Set rand_val to INT64_MAX rather than stopping the loop. This way,
       * the time we spend in the loop does not leak which element we chose. */
      rand_val = INT64_MAX;
    }
  }
  tor_assert(total_so_far == total);
  tor_assert(n_chosen == 1);
  tor_assert(i_chosen >= 0);
  tor_assert(i_chosen < n_entries);

  return i_chosen;
}

/** When weighting bridges, enforce these values as lower and upper
 * bound for believable bandwidth, because there is no way for us
 * to verify a bridge's bandwidth currently. */
#define BRIDGE_MIN_BELIEVABLE_BANDWIDTH 20000  /* 20 kB/sec */
#define BRIDGE_MAX_BELIEVABLE_BANDWIDTH 100000 /* 100 kB/sec */

/** Return the smaller of the router's configured BandwidthRate
 * and its advertised capacity, making sure to stay within the
 * interval between bridge-min-believe-bw and
 * bridge-max-believe-bw. */
static uint32_t
bridge_get_advertised_bandwidth_bounded(routerinfo_t *router)
{
  uint32_t result = router->bandwidthcapacity;
  if (result > router->bandwidthrate)
    result = router->bandwidthrate;
  if (result > BRIDGE_MAX_BELIEVABLE_BANDWIDTH)
    result = BRIDGE_MAX_BELIEVABLE_BANDWIDTH;
  else if (result < BRIDGE_MIN_BELIEVABLE_BANDWIDTH)
    result = BRIDGE_MIN_BELIEVABLE_BANDWIDTH;
  return result;
}

/** Return bw*1000, unless bw*1000 would overflow, in which case return
 * INT32_MAX. */
static INLINE int32_t
kb_to_bytes(uint32_t bw)
{
  return (bw > (INT32_MAX/1000)) ? INT32_MAX : bw*1000;
}

/** Helper function:
 * choose a random element of smartlist <b>sl</b> of nodes, weighted by
 * the advertised bandwidth of each element using the consensus
 * bandwidth weights.
 *
 * If <b>rule</b>==WEIGHT_FOR_EXIT. we're picking an exit node: consider all
 * nodes' bandwidth equally regardless of their Exit status, since there may
 * be some in the list because they exit to obscure ports. If
 * <b>rule</b>==NO_WEIGHTING, we're picking a non-exit node: weight
 * exit-node's bandwidth less depending on the smallness of the fraction of
 * Exit-to-total bandwidth.  If <b>rule</b>==WEIGHT_FOR_GUARD, we're picking a
 * guard node: consider all guard's bandwidth equally. Otherwise, weight
 * guards proportionally less.
 */
static const node_t *
smartlist_choose_node_by_bandwidth_weights(const smartlist_t *sl,
                                           bandwidth_weight_rule_t rule)
{
  u64_dbl_t *bandwidths=NULL;

  if (compute_weighted_bandwidths(sl, rule, &bandwidths) < 0)
    return NULL;

  scale_array_elements_to_u64(bandwidths, smartlist_len(sl),
                              &sl_last_total_weighted_bw);

  {
    int idx = choose_array_element_by_weight(bandwidths,
                                             smartlist_len(sl));
    tor_free(bandwidths);
    return idx < 0 ? NULL : smartlist_get(sl, idx);
  }
}

/** Given a list of routers and a weighting rule as in
 * smartlist_choose_node_by_bandwidth_weights, compute weighted bandwidth
 * values for each node and store them in a freshly allocated
 * *<b>bandwidths_out</b> of the same length as <b>sl</b>, and holding results
 * as doubles. Return 0 on success, -1 on failure. */
static int
compute_weighted_bandwidths(const smartlist_t *sl,
                            bandwidth_weight_rule_t rule,
                            u64_dbl_t **bandwidths_out)
{
  int64_t weight_scale;
  double Wg = -1, Wm = -1, We = -1, Wd = -1;
  double Wgb = -1, Wmb = -1, Web = -1, Wdb = -1;
  uint64_t weighted_bw = 0;
  u64_dbl_t *bandwidths;

  /* Can't choose exit and guard at same time */
  tor_assert(rule == NO_WEIGHTING ||
             rule == WEIGHT_FOR_EXIT ||
             rule == WEIGHT_FOR_GUARD ||
             rule == WEIGHT_FOR_MID ||
             rule == WEIGHT_FOR_DIR);

  if (smartlist_len(sl) == 0) {
    log_info(LD_CIRC,
             "Empty routerlist passed in to consensus weight node "
             "selection for rule %s",
             bandwidth_weight_rule_to_string(rule));
    return -1;
  }

  weight_scale = networkstatus_get_weight_scale_param(NULL);

  if (rule == WEIGHT_FOR_GUARD) {
    Wg = networkstatus_get_bw_weight(NULL, "Wgg", -1);
    Wm = networkstatus_get_bw_weight(NULL, "Wgm", -1); /* Bridges */
    We = 0;
    Wd = networkstatus_get_bw_weight(NULL, "Wgd", -1);

    Wgb = networkstatus_get_bw_weight(NULL, "Wgb", -1);
    Wmb = networkstatus_get_bw_weight(NULL, "Wmb", -1);
    Web = networkstatus_get_bw_weight(NULL, "Web", -1);
    Wdb = networkstatus_get_bw_weight(NULL, "Wdb", -1);
  } else if (rule == WEIGHT_FOR_MID) {
    Wg = networkstatus_get_bw_weight(NULL, "Wmg", -1);
    Wm = networkstatus_get_bw_weight(NULL, "Wmm", -1);
    We = networkstatus_get_bw_weight(NULL, "Wme", -1);
    Wd = networkstatus_get_bw_weight(NULL, "Wmd", -1);

    Wgb = networkstatus_get_bw_weight(NULL, "Wgb", -1);
    Wmb = networkstatus_get_bw_weight(NULL, "Wmb", -1);
    Web = networkstatus_get_bw_weight(NULL, "Web", -1);
    Wdb = networkstatus_get_bw_weight(NULL, "Wdb", -1);
  } else if (rule == WEIGHT_FOR_EXIT) {
    // Guards CAN be exits if they have weird exit policies
    // They are d then I guess...
    We = networkstatus_get_bw_weight(NULL, "Wee", -1);
    Wm = networkstatus_get_bw_weight(NULL, "Wem", -1); /* Odd exit policies */
    Wd = networkstatus_get_bw_weight(NULL, "Wed", -1);
    Wg = networkstatus_get_bw_weight(NULL, "Weg", -1); /* Odd exit policies */

    Wgb = networkstatus_get_bw_weight(NULL, "Wgb", -1);
    Wmb = networkstatus_get_bw_weight(NULL, "Wmb", -1);
    Web = networkstatus_get_bw_weight(NULL, "Web", -1);
    Wdb = networkstatus_get_bw_weight(NULL, "Wdb", -1);
  } else if (rule == WEIGHT_FOR_DIR) {
    We = networkstatus_get_bw_weight(NULL, "Wbe", -1);
    Wm = networkstatus_get_bw_weight(NULL, "Wbm", -1);
    Wd = networkstatus_get_bw_weight(NULL, "Wbd", -1);
    Wg = networkstatus_get_bw_weight(NULL, "Wbg", -1);

    Wgb = Wmb = Web = Wdb = weight_scale;
  } else if (rule == NO_WEIGHTING) {
    Wg = Wm = We = Wd = weight_scale;
    Wgb = Wmb = Web = Wdb = weight_scale;
  }

  if (Wg < 0 || Wm < 0 || We < 0 || Wd < 0 || Wgb < 0 || Wmb < 0 || Wdb < 0
      || Web < 0) {
    log_debug(LD_CIRC,
              "Got negative bandwidth weights. Defaulting to old selection"
              " algorithm.");
    return -1; // Use old algorithm.
  }

  Wg /= weight_scale;
  Wm /= weight_scale;
  We /= weight_scale;
  Wd /= weight_scale;

  Wgb /= weight_scale;
  Wmb /= weight_scale;
  Web /= weight_scale;
  Wdb /= weight_scale;

  bandwidths = tor_malloc_zero(sizeof(u64_dbl_t)*smartlist_len(sl));

  // Cycle through smartlist and total the bandwidth.
  SMARTLIST_FOREACH_BEGIN(sl, const node_t *, node) {
    int is_exit = 0, is_guard = 0, is_dir = 0, this_bw = 0, is_me = 0;
    double weight = 1;
    is_exit = node->is_exit && ! node->is_bad_exit;
    is_guard = node->is_possible_guard;
    is_dir = node_is_dir(node);
    if (node->rs) {
      if (!node->rs->has_bandwidth) {
        tor_free(bandwidths);
        /* This should never happen, unless all the authorites downgrade
         * to 0.2.0 or rogue routerstatuses get inserted into our consensus. */
        log_warn(LD_BUG,
                 "Consensus is not listing bandwidths. Defaulting back to "
                 "old router selection algorithm.");
        return -1;
      }
      this_bw = kb_to_bytes(node->rs->bandwidth_kb);
    } else if (node->ri) {
      /* bridge or other descriptor not in our consensus */
      this_bw = bridge_get_advertised_bandwidth_bounded(node->ri);
    } else {
      /* We can't use this one. */
      continue;
    }
    is_me = router_digest_is_me(node->identity);

    if (is_guard && is_exit) {
      weight = (is_dir ? Wdb*Wd : Wd);
    } else if (is_guard) {
      weight = (is_dir ? Wgb*Wg : Wg);
    } else if (is_exit) {
      weight = (is_dir ? Web*We : We);
    } else { // middle
      weight = (is_dir ? Wmb*Wm : Wm);
    }
    /* These should be impossible; but overflows here would be bad, so let's
     * make sure. */
    if (this_bw < 0)
      this_bw = 0;
    if (weight < 0.0)
      weight = 0.0;

    bandwidths[node_sl_idx].dbl = weight*this_bw + 0.5;
    if (is_me)
      sl_last_weighted_bw_of_me = (uint64_t) bandwidths[node_sl_idx].dbl;
  } SMARTLIST_FOREACH_END(node);

  log_debug(LD_CIRC, "Generated weighted bandwidths for rule %s based "
            "on weights "
            "Wg=%f Wm=%f We=%f Wd=%f with total bw "U64_FORMAT,
            bandwidth_weight_rule_to_string(rule),
            Wg, Wm, We, Wd, U64_PRINTF_ARG(weighted_bw));

  *bandwidths_out = bandwidths;

  return 0;
}

/** For all nodes in <b>sl</b>, return the fraction of those nodes, weighted
 * by their weighted bandwidths with rule <b>rule</b>, for which we have
 * descriptors. */
double
frac_nodes_with_descriptors(const smartlist_t *sl,
                            bandwidth_weight_rule_t rule)
{
  u64_dbl_t *bandwidths = NULL;
  double total, present;

  if (smartlist_len(sl) == 0)
    return 0.0;

  if (compute_weighted_bandwidths(sl, rule, &bandwidths) < 0) {
    int n_with_descs = 0;
    SMARTLIST_FOREACH(sl, const node_t *, node, {
      if (node_has_descriptor(node))
        n_with_descs++;
    });
    return ((double)n_with_descs) / (double)smartlist_len(sl);
  }

  total = present = 0.0;
  SMARTLIST_FOREACH_BEGIN(sl, const node_t *, node) {
    const double bw = bandwidths[node_sl_idx].dbl;
    total += bw;
    if (node_has_descriptor(node))
      present += bw;
  } SMARTLIST_FOREACH_END(node);

  tor_free(bandwidths);

  if (total < 1.0)
    return 0;

  return present / total;
}

/** Helper function:
 * choose a random node_t element of smartlist <b>sl</b>, weighted by
 * the advertised bandwidth of each element.
 *
 * If <b>rule</b>==WEIGHT_FOR_EXIT. we're picking an exit node: consider all
 * nodes' bandwidth equally regardless of their Exit status, since there may
 * be some in the list because they exit to obscure ports. If
 * <b>rule</b>==NO_WEIGHTING, we're picking a non-exit node: weight
 * exit-node's bandwidth less depending on the smallness of the fraction of
 * Exit-to-total bandwidth.  If <b>rule</b>==WEIGHT_FOR_GUARD, we're picking a
 * guard node: consider all guard's bandwidth equally. Otherwise, weight
 * guards proportionally less.
 */
static const node_t *
smartlist_choose_node_by_bandwidth(const smartlist_t *sl,
                                   bandwidth_weight_rule_t rule)
{
  unsigned int i;
  u64_dbl_t *bandwidths;
  int is_exit;
  int is_guard;
  int is_fast;
  double total_nonexit_bw = 0, total_exit_bw = 0;
  double total_nonguard_bw = 0, total_guard_bw = 0;
  double exit_weight;
  double guard_weight;
  int n_unknown = 0;
  bitarray_t *fast_bits;
  bitarray_t *exit_bits;
  bitarray_t *guard_bits;
  int me_idx = -1;

  // This function does not support WEIGHT_FOR_DIR
  // or WEIGHT_FOR_MID
  if (rule == WEIGHT_FOR_DIR || rule == WEIGHT_FOR_MID) {
    rule = NO_WEIGHTING;
  }

  /* Can't choose exit and guard at same time */
  tor_assert(rule == NO_WEIGHTING ||
             rule == WEIGHT_FOR_EXIT ||
             rule == WEIGHT_FOR_GUARD);

  if (smartlist_len(sl) == 0) {
    log_info(LD_CIRC,
             "Empty routerlist passed in to old node selection for rule %s",
             bandwidth_weight_rule_to_string(rule));
    return NULL;
  }

  /* First count the total bandwidth weight, and make a list
   * of each value.  We use UINT64_MAX to indicate "unknown". */
  bandwidths = tor_malloc_zero(sizeof(u64_dbl_t)*smartlist_len(sl));
  fast_bits = bitarray_init_zero(smartlist_len(sl));
  exit_bits = bitarray_init_zero(smartlist_len(sl));
  guard_bits = bitarray_init_zero(smartlist_len(sl));

  /* Iterate over all the routerinfo_t or routerstatus_t, and */
  SMARTLIST_FOREACH_BEGIN(sl, const node_t *, node) {
    /* first, learn what bandwidth we think i has */
    int is_known = 1;
    uint32_t this_bw = 0;
    i = node_sl_idx;

    if (router_digest_is_me(node->identity))
      me_idx = node_sl_idx;

    is_exit = node->is_exit;
    is_guard = node->is_possible_guard;
    if (node->rs) {
      if (node->rs->has_bandwidth) {
        this_bw = kb_to_bytes(node->rs->bandwidth_kb);
      } else { /* guess */
        is_known = 0;
      }
    } else if (node->ri) {
      /* Must be a bridge if we're willing to use it */
      this_bw = bridge_get_advertised_bandwidth_bounded(node->ri);
    }

    if (is_exit)
      bitarray_set(exit_bits, i);
    if (is_guard)
      bitarray_set(guard_bits, i);
    if (node->is_fast)
      bitarray_set(fast_bits, i);

    if (is_known) {
      bandwidths[i].dbl = this_bw;
      if (is_guard)
        total_guard_bw += this_bw;
      else
        total_nonguard_bw += this_bw;
      if (is_exit)
        total_exit_bw += this_bw;
      else
        total_nonexit_bw += this_bw;
    } else {
      ++n_unknown;
      bandwidths[i].dbl = -1.0;
    }
  } SMARTLIST_FOREACH_END(node);

#define EPSILON .1

  /* Now, fill in the unknown values. */
  if (n_unknown) {
    int32_t avg_fast, avg_slow;
    if (total_exit_bw+total_nonexit_bw < EPSILON) {
      /* if there's some bandwidth, there's at least one known router,
       * so no worries about div by 0 here */
      int n_known = smartlist_len(sl)-n_unknown;
      avg_fast = avg_slow = (int32_t)
        ((total_exit_bw+total_nonexit_bw)/((uint64_t) n_known));
    } else {
      avg_fast = 40000;
      avg_slow = 20000;
    }
    for (i=0; i<(unsigned)smartlist_len(sl); ++i) {
      if (bandwidths[i].dbl >= 0.0)
        continue;
      is_fast = bitarray_is_set(fast_bits, i);
      is_exit = bitarray_is_set(exit_bits, i);
      is_guard = bitarray_is_set(guard_bits, i);
      bandwidths[i].dbl = is_fast ? avg_fast : avg_slow;
      if (is_exit)
        total_exit_bw += bandwidths[i].dbl;
      else
        total_nonexit_bw += bandwidths[i].dbl;
      if (is_guard)
        total_guard_bw += bandwidths[i].dbl;
      else
        total_nonguard_bw += bandwidths[i].dbl;
    }
  }

  /* If there's no bandwidth at all, pick at random. */
  if (total_exit_bw+total_nonexit_bw < EPSILON) {
    tor_free(bandwidths);
    tor_free(fast_bits);
    tor_free(exit_bits);
    tor_free(guard_bits);
    return smartlist_choose(sl);
  }

  /* Figure out how to weight exits and guards */
  {
    double all_bw = U64_TO_DBL(total_exit_bw+total_nonexit_bw);
    double exit_bw = U64_TO_DBL(total_exit_bw);
    double guard_bw = U64_TO_DBL(total_guard_bw);
    /*
     * For detailed derivation of this formula, see
     *   http://archives.seul.org/or/dev/Jul-2007/msg00056.html
     */
    if (rule == WEIGHT_FOR_EXIT || total_exit_bw<EPSILON)
      exit_weight = 1.0;
    else
      exit_weight = 1.0 - all_bw/(3.0*exit_bw);

    if (rule == WEIGHT_FOR_GUARD || total_guard_bw<EPSILON)
      guard_weight = 1.0;
    else
      guard_weight = 1.0 - all_bw/(3.0*guard_bw);

    if (exit_weight <= 0.0)
      exit_weight = 0.0;

    if (guard_weight <= 0.0)
      guard_weight = 0.0;

    sl_last_weighted_bw_of_me = 0;
    for (i=0; i < (unsigned)smartlist_len(sl); i++) {
      tor_assert(bandwidths[i].dbl >= 0.0);

      is_exit = bitarray_is_set(exit_bits, i);
      is_guard = bitarray_is_set(guard_bits, i);
      if (is_exit && is_guard)
        bandwidths[i].dbl *= exit_weight * guard_weight;
      else if (is_guard)
        bandwidths[i].dbl *= guard_weight;
      else if (is_exit)
        bandwidths[i].dbl *= exit_weight;

      if (i == (unsigned) me_idx)
        sl_last_weighted_bw_of_me = (uint64_t) bandwidths[i].dbl;
    }
  }

#if 0
  log_debug(LD_CIRC, "Total weighted bw = "U64_FORMAT
            ", exit bw = "U64_FORMAT
            ", nonexit bw = "U64_FORMAT", exit weight = %f "
            "(for exit == %d)"
            ", guard bw = "U64_FORMAT
            ", nonguard bw = "U64_FORMAT", guard weight = %f "
            "(for guard == %d)",
            U64_PRINTF_ARG(total_bw),
            U64_PRINTF_ARG(total_exit_bw), U64_PRINTF_ARG(total_nonexit_bw),
            exit_weight, (int)(rule == WEIGHT_FOR_EXIT),
            U64_PRINTF_ARG(total_guard_bw), U64_PRINTF_ARG(total_nonguard_bw),
            guard_weight, (int)(rule == WEIGHT_FOR_GUARD));
#endif

  scale_array_elements_to_u64(bandwidths, smartlist_len(sl),
                              &sl_last_total_weighted_bw);

  {
    int idx = choose_array_element_by_weight(bandwidths,
                                             smartlist_len(sl));
    tor_free(bandwidths);
    tor_free(fast_bits);
    tor_free(exit_bits);
    tor_free(guard_bits);
    return idx < 0 ? NULL : smartlist_get(sl, idx);
  }
}

/** Choose a random element of status list <b>sl</b>, weighted by
 * the advertised bandwidth of each node */
const node_t *
node_sl_choose_by_bandwidth(const smartlist_t *sl,
                            bandwidth_weight_rule_t rule)
{ /*XXXX MOVE */
  const node_t *ret;
  if ((ret = smartlist_choose_node_by_bandwidth_weights(sl, rule))) {
    return ret;
  } else {
    return smartlist_choose_node_by_bandwidth(sl, rule);
  }
}

/** Return a random running node from the nodelist. Never
 * pick a node that is in
 * <b>excludedsmartlist</b>, or which matches <b>excludedset</b>,
 * even if they are the only nodes available.
 * If <b>CRN_NEED_UPTIME</b> is set in flags and any router has more than
 * a minimum uptime, return one of those.
 * If <b>CRN_NEED_CAPACITY</b> is set in flags, weight your choice by the
 * advertised capacity of each router.
 * If <b>CRN_ALLOW_INVALID</b> is not set in flags, consider only Valid
 * routers.
 * If <b>CRN_NEED_GUARD</b> is set in flags, consider only Guard routers.
 * If <b>CRN_WEIGHT_AS_EXIT</b> is set in flags, we weight bandwidths as if
 * picking an exit node, otherwise we weight bandwidths for picking a relay
 * node (that is, possibly discounting exit nodes).
 * If <b>CRN_NEED_DESC</b> is set in flags, we only consider nodes that
 * have a routerinfo or microdescriptor -- that is, enough info to be
 * used to build a circuit.
 */
const node_t *
router_choose_random_node(smartlist_t *excludedsmartlist,
                          routerset_t *excludedset,
                          router_crn_flags_t flags)
{ /* XXXX MOVE */
  const int need_uptime = (flags & CRN_NEED_UPTIME) != 0;
  const int need_capacity = (flags & CRN_NEED_CAPACITY) != 0;
  const int need_guard = (flags & CRN_NEED_GUARD) != 0;
  const int allow_invalid = (flags & CRN_ALLOW_INVALID) != 0;
  const int weight_for_exit = (flags & CRN_WEIGHT_AS_EXIT) != 0;
  const int need_desc = (flags & CRN_NEED_DESC) != 0;

  smartlist_t *sl=smartlist_new(),
    *excludednodes=smartlist_new();
  const node_t *choice = NULL;
  const routerinfo_t *r;
  bandwidth_weight_rule_t rule;

  tor_assert(!(weight_for_exit && need_guard));
  rule = weight_for_exit ? WEIGHT_FOR_EXIT :
    (need_guard ? WEIGHT_FOR_GUARD : WEIGHT_FOR_MID);

  /* Exclude relays that allow single hop exit circuits, if the user
   * wants to (such relays might be risky) */
  if (get_options()->ExcludeSingleHopRelays) {
    SMARTLIST_FOREACH(nodelist_get_list(), node_t *, node,
      if (node_allows_single_hop_exits(node)) {
        smartlist_add(excludednodes, node);
      });
  }

  if ((r = routerlist_find_my_routerinfo()))
    routerlist_add_node_and_family(excludednodes, r);

  router_add_running_nodes_to_smartlist(sl, allow_invalid,
                                        need_uptime, need_capacity,
                                        need_guard, need_desc);
  smartlist_subtract(sl,excludednodes);
  if (excludedsmartlist)
    smartlist_subtract(sl,excludedsmartlist);
  if (excludedset)
    routerset_subtract_nodes(sl,excludedset);

  // Always weight by bandwidth
  choice = node_sl_choose_by_bandwidth(sl, rule);

  smartlist_free(sl);
  if (!choice && (need_uptime || need_capacity || need_guard)) {
    /* try once more -- recurse but with fewer restrictions. */
    log_info(LD_CIRC,
             "We couldn't find any live%s%s%s routers; falling back "
             "to list of all routers.",
             need_capacity?", fast":"",
             need_uptime?", stable":"",
             need_guard?", guard":"");
    flags &= ~ (CRN_NEED_UPTIME|CRN_NEED_CAPACITY|CRN_NEED_GUARD);
    choice = router_choose_random_node(
                     excludedsmartlist, excludedset, flags);
  }
  smartlist_free(excludednodes);
  if (!choice) {
    log_warn(LD_CIRC,
             "No available nodes when trying to choose node. Failing.");
  }
  return choice;
}

/** Helper: given an extended nickname in <b>hexdigest</b> try to decode it.
 * Return 0 on success, -1 on failure.  Store the result into the
 * DIGEST_LEN-byte buffer at <b>digest_out</b>, the single character at
 * <b>nickname_qualifier_char_out</b>, and the MAXNICKNAME_LEN+1-byte buffer
 * at <b>nickname_out</b>.
 *
 * The recognized format is:
 *   HexName = Dollar? HexDigest NamePart?
 *   Dollar = '?'
 *   HexDigest = HexChar*20
 *   HexChar = 'a'..'f' | 'A'..'F' | '0'..'9'
 *   NamePart = QualChar Name
 *   QualChar = '=' | '~'
 *   Name = NameChar*(1..MAX_NICKNAME_LEN)
 *   NameChar = Any ASCII alphanumeric character
 */
int
hex_digest_nickname_decode(const char *hexdigest,
                           char *digest_out,
                           char *nickname_qualifier_char_out,
                           char *nickname_out)
{
  size_t len;

  tor_assert(hexdigest);
  if (hexdigest[0] == '$')
    ++hexdigest;

  len = strlen(hexdigest);
  if (len < HEX_DIGEST_LEN) {
    return -1;
  } else if (len > HEX_DIGEST_LEN && (hexdigest[HEX_DIGEST_LEN] == '=' ||
                                    hexdigest[HEX_DIGEST_LEN] == '~') &&
           len <= HEX_DIGEST_LEN+1+MAX_NICKNAME_LEN) {
    *nickname_qualifier_char_out = hexdigest[HEX_DIGEST_LEN];
    strlcpy(nickname_out, hexdigest+HEX_DIGEST_LEN+1 , MAX_NICKNAME_LEN+1);
  } else if (len == HEX_DIGEST_LEN) {
    ;
  } else {
    return -1;
  }

  if (base16_decode(digest_out, DIGEST_LEN, hexdigest, HEX_DIGEST_LEN)<0)
    return -1;
  return 0;
}

/** Helper: Return true iff the <b>identity_digest</b> and <b>nickname</b>
 * combination of a router, encoded in hexadecimal, matches <b>hexdigest</b>
 * (which is optionally prefixed with a single dollar sign).  Return false if
 * <b>hexdigest</b> is malformed, or it doesn't match.  */
int
hex_digest_nickname_matches(const char *hexdigest, const char *identity_digest,
                            const char *nickname, int is_named)
{
  char digest[DIGEST_LEN];
  char nn_char='\0';
  char nn_buf[MAX_NICKNAME_LEN+1];

  if (hex_digest_nickname_decode(hexdigest, digest, &nn_char, nn_buf) == -1)
    return 0;

  if (nn_char == '=' || nn_char == '~') {
    if (!nickname)
      return 0;
    if (strcasecmp(nn_buf, nickname))
      return 0;
    if (nn_char == '=' && !is_named)
      return 0;
  }

  return tor_memeq(digest, identity_digest, DIGEST_LEN);
}

/** Return true iff <b>router</b> is listed as named in the current
 * consensus. */
int
router_is_named(const routerinfo_t *router)
{
  const char *digest =
    networkstatus_get_router_digest_by_nickname(router->nickname);

  return (digest &&
          tor_memeq(digest, router->cache_info.identity_digest, DIGEST_LEN));
}

/** Return true iff <b>digest</b> is the digest of the identity key of a
 * trusted directory matching at least one bit of <b>type</b>.  If <b>type</b>
 * is zero, any authority is okay. */
int
router_digest_is_trusted_dir_type(const char *digest, dirinfo_type_t type)
{
  if (!trusted_dir_servers)
    return 0;
  if (authdir_mode(get_options()) && router_digest_is_me(digest))
    return 1;
  SMARTLIST_FOREACH(trusted_dir_servers, dir_server_t *, ent,
    if (tor_memeq(digest, ent->digest, DIGEST_LEN)) {
      return (!type) || ((type & ent->type) != 0);
    });
  return 0;
}

/** Return true iff <b>addr</b> is the address of one of our trusted
 * directory authorities. */
int
router_addr_is_trusted_dir(uint32_t addr)
{
  if (!trusted_dir_servers)
    return 0;
  SMARTLIST_FOREACH(trusted_dir_servers, dir_server_t *, ent,
    if (ent->addr == addr)
      return 1;
    );
  return 0;
}

/** If hexdigest is correctly formed, base16_decode it into
 * digest, which must have DIGEST_LEN space in it.
 * Return 0 on success, -1 on failure.
 */
int
hexdigest_to_digest(const char *hexdigest, char *digest)
{
  if (hexdigest[0]=='$')
    ++hexdigest;
  if (strlen(hexdigest) < HEX_DIGEST_LEN ||
      base16_decode(digest,DIGEST_LEN,hexdigest,HEX_DIGEST_LEN) < 0)
    return -1;
  return 0;
}

/** As router_get_by_id_digest,but return a pointer that you're allowed to
 * modify */
routerinfo_t *
router_get_mutable_by_digest(const char *digest)
{
  tor_assert(digest);

  if (!routerlist) return NULL;

  // routerlist_assert_ok(routerlist);

  return rimap_get(routerlist->identity_map, digest);
}

/** Return the router in our routerlist whose 20-byte key digest
 * is <b>digest</b>.  Return NULL if no such router is known. */
const routerinfo_t *
router_get_by_id_digest(const char *digest)
{
  return router_get_mutable_by_digest(digest);
}

/** Return the router in our routerlist whose 20-byte descriptor
 * is <b>digest</b>.  Return NULL if no such router is known. */
signed_descriptor_t *
router_get_by_descriptor_digest(const char *digest)
{
  tor_assert(digest);

  if (!routerlist) return NULL;

  return sdmap_get(routerlist->desc_digest_map, digest);
}

/** Return the signed descriptor for the router in our routerlist whose
 * 20-byte extra-info digest is <b>digest</b>.  Return NULL if no such router
 * is known. */
signed_descriptor_t *
router_get_by_extrainfo_digest(const char *digest)
{
  tor_assert(digest);

  if (!routerlist) return NULL;

  return sdmap_get(routerlist->desc_by_eid_map, digest);
}

/** Return the signed descriptor for the extrainfo_t in our routerlist whose
 * extra-info-digest is <b>digest</b>. Return NULL if no such extra-info
 * document is known. */
signed_descriptor_t *
extrainfo_get_by_descriptor_digest(const char *digest)
{
  extrainfo_t *ei;
  tor_assert(digest);
  if (!routerlist) return NULL;
  ei = eimap_get(routerlist->extra_info_map, digest);
  return ei ? &ei->cache_info : NULL;
}

/** Return a pointer to the signed textual representation of a descriptor.
 * The returned string is not guaranteed to be NUL-terminated: the string's
 * length will be in desc-\>signed_descriptor_len.
 *
 * If <b>with_annotations</b> is set, the returned string will include
 * the annotations
 * (if any) preceding the descriptor.  This will increase the length of the
 * string by desc-\>annotations_len.
 *
 * The caller must not free the string returned.
 */
static const char *
signed_descriptor_get_body_impl(const signed_descriptor_t *desc,
                                int with_annotations)
{
  const char *r = NULL;
  size_t len = desc->signed_descriptor_len;
  off_t offset = desc->saved_offset;
  if (with_annotations)
    len += desc->annotations_len;
  else
    offset += desc->annotations_len;

  tor_assert(len > 32);
  if (desc->saved_location == SAVED_IN_CACHE && routerlist) {
    desc_store_t *store = desc_get_store(router_get_routerlist(), desc);
    if (store && store->mmap) {
      tor_assert(desc->saved_offset + len <= store->mmap->size);
      r = store->mmap->data + offset;
    } else if (store) {
      log_err(LD_DIR, "We couldn't read a descriptor that is supposedly "
              "mmaped in our cache.  Is another process running in our data "
              "directory?  Exiting.");
      exit(1);
    }
  }
  if (!r) /* no mmap, or not in cache. */
    r = desc->signed_descriptor_body +
      (with_annotations ? 0 : desc->annotations_len);

  tor_assert(r);
  if (!with_annotations) {
    if (fast_memcmp("router ", r, 7) && fast_memcmp("extra-info ", r, 11)) {
      char *cp = tor_strndup(r, 64);
      log_err(LD_DIR, "descriptor at %p begins with unexpected string %s.  "
              "Is another process running in our data directory?  Exiting.",
              desc, escaped(cp));
      exit(1);
    }
  }

  return r;
}

/** Return a pointer to the signed textual representation of a descriptor.
 * The returned string is not guaranteed to be NUL-terminated: the string's
 * length will be in desc-\>signed_descriptor_len.
 *
 * The caller must not free the string returned.
 */
const char *
signed_descriptor_get_body(const signed_descriptor_t *desc)
{
  return signed_descriptor_get_body_impl(desc, 0);
}

/** As signed_descriptor_get_body(), but points to the beginning of the
 * annotations section rather than the beginning of the descriptor. */
const char *
signed_descriptor_get_annotations(const signed_descriptor_t *desc)
{
  return signed_descriptor_get_body_impl(desc, 1);
}

/** Return the current list of all known routers. */
routerlist_t *
router_get_routerlist(void)
{
  if (PREDICT_UNLIKELY(!routerlist)) {
    routerlist = tor_malloc_zero(sizeof(routerlist_t));
    routerlist->routers = smartlist_new();
    routerlist->old_routers = smartlist_new();
    routerlist->identity_map = rimap_new();
    routerlist->desc_digest_map = sdmap_new();
    routerlist->desc_by_eid_map = sdmap_new();
    routerlist->extra_info_map = eimap_new();

    routerlist->desc_store.fname_base = "cached-descriptors";
    routerlist->extrainfo_store.fname_base = "cached-extrainfo";

    routerlist->desc_store.type = ROUTER_STORE;
    routerlist->extrainfo_store.type = EXTRAINFO_STORE;

    routerlist->desc_store.description = "router descriptors";
    routerlist->extrainfo_store.description = "extra-info documents";
  }
  return routerlist;
}

/** Free all storage held by <b>router</b>. */
void
routerinfo_free(routerinfo_t *router)
{
  if (!router)
    return;

  tor_free(router->cache_info.signed_descriptor_body);
  tor_free(router->address);
  tor_free(router->nickname);
  tor_free(router->platform);
  tor_free(router->contact_info);
  if (router->onion_pkey)
    crypto_pk_free(router->onion_pkey);
  tor_free(router->onion_curve25519_pkey);
  if (router->identity_pkey)
    crypto_pk_free(router->identity_pkey);
  if (router->declared_family) {
    SMARTLIST_FOREACH(router->declared_family, char *, s, tor_free(s));
    smartlist_free(router->declared_family);
  }
  addr_policy_list_free(router->exit_policy);
  short_policy_free(router->ipv6_exit_policy);

  memset(router, 77, sizeof(routerinfo_t));

  tor_free(router);
}

/** Release all storage held by <b>extrainfo</b> */
void
extrainfo_free(extrainfo_t *extrainfo)
{
  if (!extrainfo)
    return;
  tor_free(extrainfo->cache_info.signed_descriptor_body);
  tor_free(extrainfo->pending_sig);

  memset(extrainfo, 88, sizeof(extrainfo_t)); /* debug bad memory usage */
  tor_free(extrainfo);
}

/** Release storage held by <b>sd</b>. */
static void
signed_descriptor_free(signed_descriptor_t *sd)
{
  if (!sd)
    return;

  tor_free(sd->signed_descriptor_body);

  memset(sd, 99, sizeof(signed_descriptor_t)); /* Debug bad mem usage */
  tor_free(sd);
}

/** Extract a signed_descriptor_t from a general routerinfo, and free the
 * routerinfo.
 */
static signed_descriptor_t *
signed_descriptor_from_routerinfo(routerinfo_t *ri)
{
  signed_descriptor_t *sd;
  tor_assert(ri->purpose == ROUTER_PURPOSE_GENERAL);
  sd = tor_malloc_zero(sizeof(signed_descriptor_t));
  memcpy(sd, &(ri->cache_info), sizeof(signed_descriptor_t));
  sd->routerlist_index = -1;
  ri->cache_info.signed_descriptor_body = NULL;
  routerinfo_free(ri);
  return sd;
}

/** Helper: free the storage held by the extrainfo_t in <b>e</b>. */
static void
extrainfo_free_(void *e)
{
  extrainfo_free(e);
}

/** Free all storage held by a routerlist <b>rl</b>. */
void
routerlist_free(routerlist_t *rl)
{
  if (!rl)
    return;
  rimap_free(rl->identity_map, NULL);
  sdmap_free(rl->desc_digest_map, NULL);
  sdmap_free(rl->desc_by_eid_map, NULL);
  eimap_free(rl->extra_info_map, extrainfo_free_);
  SMARTLIST_FOREACH(rl->routers, routerinfo_t *, r,
                    routerinfo_free(r));
  SMARTLIST_FOREACH(rl->old_routers, signed_descriptor_t *, sd,
                    signed_descriptor_free(sd));
  smartlist_free(rl->routers);
  smartlist_free(rl->old_routers);
  if (routerlist->desc_store.mmap)
    tor_munmap_file(routerlist->desc_store.mmap);
  if (routerlist->extrainfo_store.mmap)
    tor_munmap_file(routerlist->extrainfo_store.mmap);
  tor_free(rl);

  router_dir_info_changed();
}

/** Log information about how much memory is being used for routerlist,
 * at log level <b>severity</b>. */
void
dump_routerlist_mem_usage(int severity)
{
  uint64_t livedescs = 0;
  uint64_t olddescs = 0;
  if (!routerlist)
    return;
  SMARTLIST_FOREACH(routerlist->routers, routerinfo_t *, r,
                    livedescs += r->cache_info.signed_descriptor_len);
  SMARTLIST_FOREACH(routerlist->old_routers, signed_descriptor_t *, sd,
                    olddescs += sd->signed_descriptor_len);

  tor_log(severity, LD_DIR,
      "In %d live descriptors: "U64_FORMAT" bytes.  "
      "In %d old descriptors: "U64_FORMAT" bytes.",
      smartlist_len(routerlist->routers), U64_PRINTF_ARG(livedescs),
      smartlist_len(routerlist->old_routers), U64_PRINTF_ARG(olddescs));
}

/** Debugging helper: If <b>idx</b> is nonnegative, assert that <b>ri</b> is
 * in <b>sl</b> at position <b>idx</b>. Otherwise, search <b>sl</b> for
 * <b>ri</b>.  Return the index of <b>ri</b> in <b>sl</b>, or -1 if <b>ri</b>
 * is not in <b>sl</b>. */
static INLINE int
routerlist_find_elt_(smartlist_t *sl, void *ri, int idx)
{
  if (idx < 0) {
    idx = -1;
    SMARTLIST_FOREACH(sl, routerinfo_t *, r,
                      if (r == ri) {
                        idx = r_sl_idx;
                        break;
                      });
  } else {
    tor_assert(idx < smartlist_len(sl));
    tor_assert(smartlist_get(sl, idx) == ri);
  };
  return idx;
}

/** Insert an item <b>ri</b> into the routerlist <b>rl</b>, updating indices
 * as needed.  There must be no previous member of <b>rl</b> with the same
 * identity digest as <b>ri</b>: If there is, call routerlist_replace
 * instead.
 */
static void
routerlist_insert(routerlist_t *rl, routerinfo_t *ri)
{
  routerinfo_t *ri_old;
  signed_descriptor_t *sd_old;
  {
    const routerinfo_t *ri_generated = router_get_my_routerinfo();
    tor_assert(ri_generated != ri);
  }
  tor_assert(ri->cache_info.routerlist_index == -1);

  ri_old = rimap_set(rl->identity_map, ri->cache_info.identity_digest, ri);
  tor_assert(!ri_old);

  sd_old = sdmap_set(rl->desc_digest_map,
                     ri->cache_info.signed_descriptor_digest,
                     &(ri->cache_info));
  if (sd_old) {
    int idx = sd_old->routerlist_index;
    sd_old->routerlist_index = -1;
    smartlist_del(rl->old_routers, idx);
    if (idx < smartlist_len(rl->old_routers)) {
       signed_descriptor_t *d = smartlist_get(rl->old_routers, idx);
       d->routerlist_index = idx;
    }
    rl->desc_store.bytes_dropped += sd_old->signed_descriptor_len;
    sdmap_remove(rl->desc_by_eid_map, sd_old->extra_info_digest);
    signed_descriptor_free(sd_old);
  }

  if (!tor_digest_is_zero(ri->cache_info.extra_info_digest))
    sdmap_set(rl->desc_by_eid_map, ri->cache_info.extra_info_digest,
              &ri->cache_info);
  smartlist_add(rl->routers, ri);
  ri->cache_info.routerlist_index = smartlist_len(rl->routers) - 1;
  nodelist_set_routerinfo(ri, NULL);
  router_dir_info_changed();
#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
}

/** Adds the extrainfo_t <b>ei</b> to the routerlist <b>rl</b>, if there is a
 * corresponding router in rl-\>routers or rl-\>old_routers.  Return true iff
 * we actually inserted <b>ei</b>.  Free <b>ei</b> if it isn't inserted. */
static int
extrainfo_insert(routerlist_t *rl, extrainfo_t *ei)
{
  int r = 0;
  routerinfo_t *ri = rimap_get(rl->identity_map,
                               ei->cache_info.identity_digest);
  signed_descriptor_t *sd =
    sdmap_get(rl->desc_by_eid_map, ei->cache_info.signed_descriptor_digest);
  extrainfo_t *ei_tmp;

  {
    extrainfo_t *ei_generated = router_get_my_extrainfo();
    tor_assert(ei_generated != ei);
  }

  if (!ri) {
    /* This router is unknown; we can't even verify the signature. Give up.*/
    goto done;
  }
  if (routerinfo_incompatible_with_extrainfo(ri, ei, sd, NULL)) {
    goto done;
  }

  /* Okay, if we make it here, we definitely have a router corresponding to
   * this extrainfo. */

  ei_tmp = eimap_set(rl->extra_info_map,
                     ei->cache_info.signed_descriptor_digest,
                     ei);
  r = 1;
  if (ei_tmp) {
    rl->extrainfo_store.bytes_dropped +=
      ei_tmp->cache_info.signed_descriptor_len;
    extrainfo_free(ei_tmp);
  }

 done:
  if (r == 0)
    extrainfo_free(ei);

#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
  return r;
}

#define should_cache_old_descriptors() \
  directory_caches_dir_info(get_options())

/** If we're a directory cache and routerlist <b>rl</b> doesn't have
 * a copy of router <b>ri</b> yet, add it to the list of old (not
 * recommended but still served) descriptors. Else free it. */
static void
routerlist_insert_old(routerlist_t *rl, routerinfo_t *ri)
{
  {
    const routerinfo_t *ri_generated = router_get_my_routerinfo();
    tor_assert(ri_generated != ri);
  }
  tor_assert(ri->cache_info.routerlist_index == -1);

  if (should_cache_old_descriptors() &&
      ri->purpose == ROUTER_PURPOSE_GENERAL &&
      !sdmap_get(rl->desc_digest_map,
                 ri->cache_info.signed_descriptor_digest)) {
    signed_descriptor_t *sd = signed_descriptor_from_routerinfo(ri);
    sdmap_set(rl->desc_digest_map, sd->signed_descriptor_digest, sd);
    smartlist_add(rl->old_routers, sd);
    sd->routerlist_index = smartlist_len(rl->old_routers)-1;
    if (!tor_digest_is_zero(sd->extra_info_digest))
      sdmap_set(rl->desc_by_eid_map, sd->extra_info_digest, sd);
  } else {
    routerinfo_free(ri);
  }
#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
}

/** Remove an item <b>ri</b> from the routerlist <b>rl</b>, updating indices
 * as needed. If <b>idx</b> is nonnegative and smartlist_get(rl-&gt;routers,
 * idx) == ri, we don't need to do a linear search over the list to decide
 * which to remove.  We fill the gap in rl-&gt;routers with a later element in
 * the list, if any exists. <b>ri</b> is freed.
 *
 * If <b>make_old</b> is true, instead of deleting the router, we try adding
 * it to rl-&gt;old_routers. */
void
routerlist_remove(routerlist_t *rl, routerinfo_t *ri, int make_old, time_t now)
{
  routerinfo_t *ri_tmp;
  extrainfo_t *ei_tmp;
  int idx = ri->cache_info.routerlist_index;
  tor_assert(0 <= idx && idx < smartlist_len(rl->routers));
  tor_assert(smartlist_get(rl->routers, idx) == ri);

  nodelist_remove_routerinfo(ri);

  /* make sure the rephist module knows that it's not running */
  rep_hist_note_router_unreachable(ri->cache_info.identity_digest, now);

  ri->cache_info.routerlist_index = -1;
  smartlist_del(rl->routers, idx);
  if (idx < smartlist_len(rl->routers)) {
    routerinfo_t *r = smartlist_get(rl->routers, idx);
    r->cache_info.routerlist_index = idx;
  }

  ri_tmp = rimap_remove(rl->identity_map, ri->cache_info.identity_digest);
  router_dir_info_changed();
  tor_assert(ri_tmp == ri);

  if (make_old && should_cache_old_descriptors() &&
      ri->purpose == ROUTER_PURPOSE_GENERAL) {
    signed_descriptor_t *sd;
    sd = signed_descriptor_from_routerinfo(ri);
    smartlist_add(rl->old_routers, sd);
    sd->routerlist_index = smartlist_len(rl->old_routers)-1;
    sdmap_set(rl->desc_digest_map, sd->signed_descriptor_digest, sd);
    if (!tor_digest_is_zero(sd->extra_info_digest))
      sdmap_set(rl->desc_by_eid_map, sd->extra_info_digest, sd);
  } else {
    signed_descriptor_t *sd_tmp;
    sd_tmp = sdmap_remove(rl->desc_digest_map,
                          ri->cache_info.signed_descriptor_digest);
    tor_assert(sd_tmp == &(ri->cache_info));
    rl->desc_store.bytes_dropped += ri->cache_info.signed_descriptor_len;
    ei_tmp = eimap_remove(rl->extra_info_map,
                          ri->cache_info.extra_info_digest);
    if (ei_tmp) {
      rl->extrainfo_store.bytes_dropped +=
        ei_tmp->cache_info.signed_descriptor_len;
      extrainfo_free(ei_tmp);
    }
    if (!tor_digest_is_zero(ri->cache_info.extra_info_digest))
      sdmap_remove(rl->desc_by_eid_map, ri->cache_info.extra_info_digest);
    routerinfo_free(ri);
  }
#ifdef DEBUG_ROUTERLIST
  routerlist_assert_ok(rl);
#endif
}

/** Remove a signed_descriptor_t <b>sd</b> from <b>rl</b>-\>old_routers, and
 * adjust <b>rl</b> as appropriate.  <b>idx</b> is -1, or the index of
 * <b>sd</b>. */
static void
routerlist_remove_old(routerlist_t *rl, signed_descriptor_t *sd, int idx)
{
  signed_descriptor_t *sd_tmp;
  extrainfo_t *ei_tmp;
  desc_store_t *store;
  if (idx == -1) {
    idx = sd->routerlist_index;
  }
  tor_assert(0 <= idx && idx < smartlist_len(rl->old_routers));
  /* XXXX edmanm's bridge relay triggered the following assert while
   * running 0.2.0.12-alpha.  If anybody triggers this again, see if we
   * can get a backtrace. */
  tor_assert(smartlist_get(rl->old_routers, idx) == sd);
  tor_assert(idx == sd->routerlist_index);

  sd->routerlist_index = -1;
  smartlist_del(rl->old_routers, idx);
  if (idx < smartlist_len(rl->old_routers)) {
    signed_descriptor