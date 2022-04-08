/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define ADDRESSMAP_PRIVATE

#include "or.h"
#include "addressmap.h"
#include "circuituse.h"
#include "config.h"
#include "connection_edge.h"
#include "control.h"
#include "dns.h"
#include "routerset.h"
#include "nodelist.h"

/** A client-side struct to remember requests to rewrite addresses
 * to new addresses. These structs are stored in the hash table
 * "addressmap" below.
 *
 * There are 5 ways to set an address mapping:
 * - A MapAddress command from the controller [permanent]
 * - An AddressMap directive in the torrc [permanent]
 * - When a TrackHostExits torrc directive is triggered [temporary]
 * - When a DNS resolve succeeds [temporary]
 * - When a DNS resolve fails [temporary]
 *
 * When an addressmap request is made but one is already registered,
 * the new one is replaced only if the currently registered one has
 * no "new_address" (that is, it's in the process of DNS resolve),
 * or if the new one is permanent (expires==0 or 1).
 *
 * (We overload the 'expires' field, using "0" for mappings set via
 * the configuration file, "1" for mappings set from the control
 * interface, and other values for DNS and TrackHostExit mappings that can
 * expire.)
 *
 * A mapping may be 'wildcarded'.  If "src_wildcard" is true, then
 * any address that ends with a . followed by the key for this entry will
 * get remapped by it.  If "dst_wildcard" is also true, then only the
 * matching suffix of such addresses will get replaced by new_address.
 */
typedef struct {
  char *new_address;
  time_t expires;
  ENUM_BF(addressmap_entry_source_t) source:3;
  unsigned src_wildcard:1;
  unsigned dst_wildcard:1;
  short num_resolve_failures;
} addressmap_entry_t;

/** Entry for mapping addresses to which virtual address we mapped them to. */
typedef struct {
  char *ipv4_address;
  char *ipv6_address;
  char *hostname_address;
} virtaddress_entry_t;

/** A hash table to store client-side address rewrite instructions. */
static strmap_t *addressmap=NULL;

/**
 * Table mapping addresses to which virtual address, if any, we
 * assigned them to.
 *
 * We maintain the following invariant: if [A,B] is in
 * virtaddress_reversemap, then B must be a virtual address, and [A,B]
 * must be in addressmap.  We do not require that the converse hold:
 * if it fails, then we could end up mapping two virtual addresses to
 * the same address, which is no disaster.
 **/
static strmap_t *virtaddress_reversemap=NULL;

/** Initialize addressmap. */
void
addressmap_init(void)
{
  addressmap = strmap_new();
  virtaddress_reversemap = strmap_new();
}

/** Free the memory associated with the addressmap entry <b>_ent</b>. */
static void
addressmap_ent_free(void *_ent)
{
  addressmap_entry_t *ent;
  if (!_ent)
    return;

  ent = _ent;
  tor_free(ent->new_address);
  tor_free(ent);
}

/** Free storage held by a virtaddress_entry_t* entry in <b>ent</b>. */
static void
addressmap_virtaddress_ent_free(void *_ent)
{
  virtaddress_entry_t *ent;
  if (!_ent)
    return;

  ent = _ent;
  tor_free(ent->ipv4_address);
  tor_free(ent->hostname_address);
  tor_free(ent);
}

/** Free storage held by a virtaddress_entry_t* entry in <b>ent</b>. */
static void
addressmap_virtaddress_remove(const char *address, addressmap_entry_t *ent)
{
  if (ent && ent->new_address &&
      address_is_in_virtual_range(ent->new_address)) {
    virtaddress_entry_t *ve =
      strmap_get(virtaddress_reversemap, ent->new_address);
    /*log_fn(LOG_NOTICE,"remove reverse mapping for %s",ent->new_address);*/
    if (ve) {
      if (!strcmp(address, ve->ipv4_address))
        tor_free(ve->ipv4_address);
      if (!strcmp(address, ve->hostname_address))
        tor_free(ve->hostname_address);
      if (!ve->ipv4_address && !ve->hostname_address) {
        tor_free(ve);
        strmap_remove(virtaddress_reversemap, ent->new_address);
      }
    }
  }
}

/** Remove <b>ent</b> (which must be mapped to by <b>address</b>) from the
 * client address maps. */
static void
addressmap_ent_remove(const char *address, addressmap_entry_t *ent)
{
  addressmap_virtaddress_remove(address, ent);
  addressmap_ent_free(ent);
}

/** Unregister all TrackHostExits mappings from any address to
 * *.exitname.exit. */
void
clear_trackexithost_mappings(const char *exitname)
{
  char *suffix = NULL;
  if (!addressmap || !exitname)
    return;
  tor_asprintf(&suffix, ".%s.exit", exitname);
  tor_strlower(suffix);

  STRMAP_FOREACH_MODIFY(addressmap, address, addressmap_entry_t *, ent) {
    if (ent->source == ADDRMAPSRC_TRACKEXIT &&
        !strcmpend(ent->new_address, suffix)) {
      addressmap_ent_remove(address, ent);
      MAP_DEL_CURRENT(address);
    }
  } STRMAP_FOREACH_END;

  tor_free(suffix);
}

/** Remove all TRACKEXIT mappings from the addressmap for which the target
 * host is unknown or no longer allowed, or for which the source address
 * is no longer in trackexithosts. */
void
addressmap_clear_excluded_trackexithosts(const or_options_t *options)
{
  const routerset_t *allow_nodes = options->ExitNodes;
  const routerset_t *exclude_nodes = options->ExcludeExitNodesUnion_;

  if (!addressmap)
    return;
  if (routerset_is_empty(allow_nodes))
    allow_nodes = NULL;
  if (allow_nodes == NULL && routerset_is_empty(exclude_nodes))
    return;

  STRMAP_FOREACH_MODIFY(addressmap, address, addressmap_entry_t *, ent) {
    size_t len;
    const char *target = ent->new_address, *dot;
    char *nodename;
    const node_t *node;

    if (!target) {
      /* DNS resolving in progress */
      continue;
    } else if (strcmpend(target, ".exit")) {
      /* Not a .exit mapping */
      continue;
    } else if (ent->source != ADDRMAPSRC_TRACKEXIT) {
      /* Not a trackexit mapping. */
      continue;
    }
    len = strlen(target);
    if (len < 6)
      continue; /* malformed. */
    dot = target + len - 6; /* dot now points to just before .exit */
    while (dot > target && *dot != '.')
      dot--;
    if (*dot == '.') dot++;
    nodename = tor_strndup(dot, len-5-(dot-target));;
    node = node_get_by_nickname(nodename, 0);
    tor_free(nodename);
    if (!node ||
        (allow_nodes && !routerset_contains_node(allow_nodes, node)) ||
        routerset_contains_node(exclude_nodes, node) ||
        !hostname_in_track_host_exits(options, address)) {
      /* We don't know this one, or we want to be rid of it. */
      addressmap_ent_remove(address, ent);
      MAP_DEL_CURRENT(address);
    }
  } STRMAP_FOREACH_END;
}

/** Return true iff <b>address</b> is one that we are configured to
 * automap on resolve according to <b>options</b>. */
int
addressmap_address_should_automap(const char *address,
                                  const or_options_t *options)
{
  const smartlist_t *suffix_list = options->AutomapHostsSuffixes;

  if (!suffix_list)
    return 0;

  SMARTLIST_FOREACH_BEGIN(suffix_list, const char *, suffix) {
    if (!strcasecmpend(address, suffix))
      return 1;
  } SMARTLIST_FOREACH_END(suffix);
  return 0;
}

/** Remove all AUTOMAP mappings from the addressmap for which the
 * source address no longer matches AutomapHostsSuffixes, which is
 * no longer allowed by AutomapHostsOnResolve, or for which the
 * target address is no longer in the virtual network. */
void
addressmap_clear_invalid_automaps(const or_options_t *options)
{
  int clear_all = !options->AutomapHostsOnResolve;
  const smartlist_t *suffixes = options->AutomapHostsSuffixes;

  if (!addressmap)
    return;

  if (!suffixes)
    clear_all = 1; /* This should be impossible, but let's be sure. */

  STRMAP_FOREACH_MODIFY(addressmap, src_address, addressmap_entry_t *, ent) {
    int remove = clear_all;
    if (ent->source != ADDRMAPSRC_AUTOMAP)
      continue; /* not an automap mapping. */

    if (!remove) {
      remove = ! addressmap_address_should_automap(src_address, options);
    }

    if (!remove && ! address_is_in_virtual_range(ent->new_address))
      remove = 1;

    if (remove) {
      addressmap_ent_remove(src_address, ent);
      MAP_DEL_CURRENT(src_address);
    }
  } STRMAP_FOREACH_END;
}

/** Remove all entries from the addressmap that were set via the
 * configuration file or the command line. */
void
addressmap_clear_configured(void)
{
  addressmap_get_mappings(NULL, 0, 0, 0);
}

/** Remove all entries from the addressmap that are set to expire, ever. */
void
addressmap_clear_transient(void)
{
  addressmap_get_mappings(NULL, 2, TIME_MAX, 0);
}

/** Clean out entries from the addressmap cache that were
 * added long enough ago that they are no longer valid.
 */
void
addressmap_clean(time_t now)
{
  addressmap_get_mappings(NULL, 2, now, 0);
}

/** Free all the elements in the addressmap, and free the addressmap
 * itself. */
void
addressmap_free_all(void)
{
  strmap_free(addressmap, addressmap_ent_free);
  addressmap = NULL;

  strmap_free(virtaddress_reversemap, addressmap_virtaddress_ent_free);
  virtaddress_reversemap = NULL;
}

/** Try to find a match for AddressMap expressions that use
 *  wildcard notation such as '*.c.d *.e.f' (so 'a.c.d' will map to 'a.e.f') or
 *  '*.c.d a.b.c' (so 'a.c.d' will map to a.b.c).
 *  Return the matching entry in AddressMap or NULL if no match is found.
 *  For expressions such as '*.c.d *.e.f', truncate <b>address</b> 'a.c.d'
 *  to 'a' before we return the matching AddressMap entry.
 *
 * This function does not handle the case where a pattern of the form "*.c.d"
 * matches the address c.d -- that's done by the main addressmap_rewrite
 * function.
 */
static addressmap_entry_t *
addressmap_match_superdomains(char *address)
{
  addressmap_entry_t *val;
  char *cp;

  cp = address;
  while ((cp = strchr(cp, '.'))) {
    /* cp now points to a suffix of address that begins with a . */
    val = strmap_get_lc(addressmap, cp+1);
    if (val && val->src_wildcard) {
      if (val->dst_wildcard)
        *cp = '\0';
      return val;
    }
    ++cp;
  }
  return NULL;
}

/** Look at address, and rewrite it until it doesn't want any
 * more rewrites; but don't get into an infinite loop.
 * Don't write more than maxlen chars into address.  Return true if the
 * address changed; false otherwise.  Set *<b>expires_out</b> to the
 * expiry time of the result, or to <b>time_max</b> if the result does
 * not expire.
 *
 * If <b>exit_source_out</b> is non-null, we set it as follows.  If we the
 * address starts out as a non-exit address, and we remap it to an .exit
 * address at any point, then set *<b>exit_source_out</b> to the
 * address_entry_source_t of the first such rule.  Set *<b>exit_source_out</b>
 * to ADDRMAPSRC_NONE if there is no such rewrite, or if the original address
 * was a .exit.
 */
int
addressmap_rewrite(char *address, size_t maxlen,
                   unsigned flags,
                   time_t *expires_out,
                   addressmap_entry_source_t *exit_source_out)
{
  addressmap_entry_t *ent;
  int rewrites;
  time_t expires = TIME_MAX;
  addressmap_entry_source_t exit_source = ADDRMAPSRC_NONE;
  char *addr_orig = tor_strdup(address);
  char *log_addr_orig = NULL;

  for (rewrites = 0; rewrites < 16; rewrites++) {
    int exact_match = 0;
    log_addr_orig = tor_strdup(escaped_safe_str_client(address));

    ent = strmap_get(addressmap, address);

    if (!ent || !ent->new_address) {
      ent = addressmap_match_superdomains(address);
    } else {
      if (ent->src_wildcard && !ent->dst_wildcard &&
          !strcasecmp(address, ent->new_address)) {
        /* This is a rule like *.example.com example.com, and we just got
         * "example.com" */
        goto done;
      }

      exact_match = 1;
    }

    if (!ent || !ent->new_address) {
      goto done;
    }

    if (ent && ent->source == ADDRMAPSRC_DNS) {
      sa_family_t f;
      tor_addr_t tmp;
      f = tor_addr_parse(&tmp, ent->new_address);
      if (f == AF_INET && !(flags & AMR_FLAG_USE_IPV4_DNS))
        goto done;
      else if (f == AF_INET6 && !(flags & AMR_FLAG_USE_IPV6_DNS))
        goto done;
    }

    if (ent->dst_wildcard && !exact_match) {
      strlcat(address, ".", maxlen);
      strlcat(address, ent->new_address, maxlen);
    } else {
      strlcpy(address, ent->new_address, maxlen);
    }

    if (!strcmpend(address, ".exit") &&
        strcmpend(addr_orig, ".exit") &&
        exit_source == ADDRMAPSRC_NONE) {
      exit_source = ent->source;
    }

    log_info(LD_APP, "Addressmap: rewriting %s to %s",
             log_addr_orig, escaped_safe_str_client(address));
    if (ent->expires > 1 && ent->expires < expires)
      expires = ent->expires;

    tor_free(log_addr_orig);
  }
  log_warn(LD_CONFIG,
           "Loop detected: we've rewritten %s 16 times! Using it as-is.",
           escaped_safe_str_client(address));
  /* it's fine to rewrite a rewrite, but don't loop forever */

 done:
  tor_free(addr_orig);
  tor_free(log_addr_orig);
  if (exit_source_out)
    *exit_source_out = exit_source;
  if (expires_out)
    *expires_out = TIME_MAX;
  return (rewrites > 0);
}

/** If we have a cached reverse DNS entry for the address stored in the
 * <b>maxlen</b>-byte buffer <b>address</b> (typically, a dotted quad) then
 * rewrite to the cached value and return 1.  Otherwise return 0.  Set
 * *<b>expires_out</b> to the expiry time of the result, or to <b>time_max</b>
 * if the result does not expire. */
int
addressmap_rewrite_reverse(char *address, size_t maxlen, unsigned flags,
                           time_t *expires_out)
{
  char *s, *cp;
  addressmap_entry_t *ent;
  int r = 0;
  {
    sa_family_t f;
    tor_addr_t tmp;
    f = tor_addr_parse(&tmp, address);
    if (f == AF_INET && !(flags & AMR_FLAG_USE_IPV4_DNS))
      return 0;
    else if (f == AF_INET6 && !(flags & AMR_FLAG_USE_IPV6_DNS))
      return 0;
  }

  tor_asprintf(&s, "REVERSE[%s]", address);
  ent = strmap_get(addressmap, s);
  if (ent) {
    cp = tor_strdup(escaped_safe_str_client(ent->new_address));
    log_info(LD_APP, "Rewrote reverse lookup %s -> %s",
             escaped_safe_str_client(s), cp);
    tor_free(cp);
    strlcpy(address, ent->new_address, maxlen);
    r = 1;
  }

  if (expires_out)
    *expires_out = (ent && ent->expires > 1) ? ent->expires : TIME_MAX;

  tor_free(s);
  return r;
}

/** Return 1 if <b>address</b> is already registered, else return 0. If address
 * is already registered, and <b>update_expires</b> is non-zero, then update
 * the expiry time on the mapping with update_expires if it is a
 * mapping created by TrackHostExits. */
int
addressmap_have_mapping(const char *address, int update_expiry)
{
  addressmap_entry_t *ent;
  if (!(ent=strmap_get_lc(addressmap, address)))
    return 0;
  if (update_expiry && ent->source==ADDRMAPSRC_TRACKEXIT)
    ent->expires=time(NULL) + update_expiry;
  return 1;
}

/** Register a request to map <b>address</b> to <b>new_address</b>,
 * which will expire on <b>expires</b> (or 0 if never expires from
 * config file, 1 if never expires from controller, 2 if never expires
 * (virtual address mapping) from the controller.)
 *
 * <b>new_address</b> should be a newly dup'ed string, which we'll use or
 * free as appropriate. We will leave address alone.
 *
 * If <b>wildcard_addr</b> is true, then the mapping will match any address
 * equal to <b>address</b>, or any address ending with a period followed by
 * <b>address</b>.  If <b>wildcard_addr</b> and <b>wildcard_new_addr</b> are
 * both true, the mapping will rewrite addresses that end with
 * ".<b>address</b>" into ones that end with ".<b>new_address</b>."
 *
 * If <b>new_address</b> is NULL, or <b>new_address</b> is equal to
 * <b>address</b> and <b>wildcard_addr</b> is equal to
 * <b>wildcard_new_addr</b>, remove any mappings that exist from
 * <b>address</b>.
 *
 *
 * It is an error to set <b>wildcard_new_addr</b> if <b>wildcard_addr</b> is
 * not set. */
void
addressmap_register(const char *address, char *new_address, time_t expires,
                    addressmap_entry_source_t source,
                    const int wildcard_addr,
                    const int wildcard_new_addr)
{
  addressmap_entry_t *ent;

  if (wildcard_new_addr)
    tor_assert(wildcard_addr);

  ent = strmap_get(addressmap, address);
  if (!new_address || (!strcasecmp(address,new_address) &&
                       wildcard_addr == wildcard_new_addr)) {
    /* Remove the mapping, if any. */
    tor_free(new_address);
    if (ent) {
      addressmap_ent_remove(address,ent);
      strmap_remove(addressmap, address);
    }
    return;
  }
  if (!ent) { /* make a new one and register it */
    ent = tor_malloc_zero(sizeof(addressmap_entry_t));
    strmap_set(addressmap, address, ent);
  } else if (ent->new_address) { /* we need to clean up the old mapping. */
    if (expires > 1) {
      log_info(LD_APP,"Temporary addressmap ('%s' to '%s') not performed, "
               "since it's already mapped to '%s'",
      safe_str_client(address),
      safe_str_client(new_address),
      safe_str_client(ent->new_address));
      tor_free(new_address);
      return;
    }
    if (address_is_in_virtual_range(ent->new_address) &&
        expires != 2) {
      /* XXX This isn't the perfect test; we want to avoid removing
       * mappings set