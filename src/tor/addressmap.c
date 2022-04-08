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
  int clear_all = !options->Aut