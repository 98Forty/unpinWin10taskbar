/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "address.h"
#include "config.h"
#include "control.h"
#include "dirserv.h"
#include "geoip.h"
#include "onion_main.h"
#include "microdesc.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "policies.h"
#include "rendservice.h"
#include "router.h"
#include "routerlist.h"
#include "routerset.h"

#include <string.h>

static void nodelist_drop_node(node_t *node, int remove_from_ht);
static void node_free(node_t *node);
static void update_router_have_minimum_dir_info(void);
static double get_frac_paths_needed_for_circs(const or_options_t *options,
                                              const networkstatus_t *ns);

/** A nodelist_t holds a node_t object for every router we're "willing to use
 * for something".  Specifically, it should hold a node_t for every node that
 * is currently in the routerlist, or currently in the consensus we're using.
 */
typedef struct nodelist_t {
  /* A list of all the nodes. */
  smartlist_t *nodes;
  /* Hash table to map from node ID digest to node. */
  HT_HEAD(nodelist_map, node_t) nodes_by_id;

} nodelist_t;

static INLINE unsigned int
node_id_hash(const node_t *node)
{
#if SIZEOF_INT == 4
  const uint32_t *p = (const uint32_t*)node->identity;
  return p[0] ^ p[1] ^ p[2] ^ p[3] ^ p[4];
#elif SIZEOF_INT == 8
  const uint64_t *p = (const uint32_t*)node->identity;
  const uint32_t *p32 = (const uint32_t*)node->identity;
  return p[0] ^ p[1] ^ p32[4];
#endif
}

static INLINE unsigned int
node_id_eq(const node_t *node1, const node_t *node2)
{
  return tor_memeq(node1->identity, node2->identity, DIGEST_LEN);
}

HT_PROTOTYPE(nodelist_map, node_t, ht_ent, node_id_hash, node_id_eq);
HT_GENERATE(nodelist_map, node_t, ht_ent, node_id_hash, node_id_eq,
            0.6, malloc, realloc, free);

/** The global nodelist. */
static nodelist_t *the_nodelist=NULL;

/** Create an empty nodelist if we haven't done so already. */
static void
init_nodelist(void)
{
  if (PREDICT_UNLIKELY(the_nodelist == NULL)) {
    the_nodelist = tor_malloc_zero(sizeof(nodelist_t));
    HT_INIT(nodelist_map, &the_nodelist->nodes_by_id);
    the_nodelist->nodes = smartlist_new();
  }
}

/** As node_get_by_id, but returns a non-const pointer */
node_t *
node_get_mutable_by_id(const char *identity_digest)
{
  node_t search, *node;
  if (PREDICT_UNLIKELY(the_nodelist == NULL))
    return NULL;

  memcpy(&search.identity, identity_digest, DIGEST_LEN);
  node = HT_FIND(nodelist_map, &the_nodelist->nodes_by_id, &search);
  return node;
}

/** Return the node_t whose identity is <b>identity_digest</b>, or NULL
 * if no such node exists. */
const node_t *
node_get_by_id(const char *identity_digest)
{
  return node_get_mutable_by_id(identity_digest);
}

/** Internal: return the node_t whose identity_digest is
 * <b>identity_digest</b>.  If none exists, create a new one, add it to the
 * nodelist, and return it.
 *
 * Requires that the nodelist be initialized.
 */
static node_t *
node_get_or_create(const char *identity_digest)
{
  node_t *node;

  if ((node = node_get_mutable_by_id(identity_digest)))
    return node;

  node = tor_malloc_zero(sizeof(node_t));
  memcpy(node->identity, identity_digest, DIGEST_LEN);
  HT_INSERT(nodelist_map, &the_nodelist->nodes_by_id, node);

  smartlist_add(the_nodelist->nodes, node);
  node->nodelist_idx = smartlist_len(the_nodelist->nodes) - 1;

  node->country = -1;

  return node;
}

/** Called when a node's address changes. */
static void
node_addrs_changed(node_t *node)
{
  node->last_reachable = node->last_reachable6 = 0;
  node->country = -1;
}

/** Add <b>ri</b> to an appropriate node in the nodelist.  If we replace an
 * old routerinfo, and <b>ri_old_out</b> is not NULL, set *<b>ri_old_out</b>
 * to the previous routerinfo.
 */
node_t *
nodelist_set_routerinfo(routerinfo_t *ri, routerinfo_t **ri_old_out)
{
  node_t *node;
  const char *id_digest;
  int had_router = 0;
  tor_assert(ri);

  init_nodelist();
  id_digest = ri->cache_info.identity_digest;
  node = node_get_or_create(id_digest);

  if (node->ri) {
    if (!routers_have_same_or_addrs(node->ri, ri)) {
      node_addrs_changed(node);
    }
    had_router = 1;
    if (ri_old_out)
      *ri_old_out = node->ri;
  } else {
    if (ri_old_out)
      *ri_old_out = NULL;
  }
  node->ri = ri;

  if (node->country == -1)
    node_set_country(node);

  if (authdir_mode(get_options()) && !had_router) {
    const char *discard=NULL;
    uint32_t status = dirserv_router_get_status(ri, &discard);
    dirserv_set_node_flags_from_authoritative_status(node, status);
  }

  return node;
}

/** Set the appropriate node_t to use <b>md</b> as its microdescriptor.
 *
 * Called when a new microdesc has arrived and the usable consensus flavor
 * is "microdesc".
 **/
node_t *
nodelist_add_microdesc(microdesc_t *md)
{
  networkstatus_t *ns =
    networkstatus_get_latest_consensus_by_flavor(FLAV_MICRODESC);
  const routerstatus_t *rs;
  node_t *node;
  if (ns == NULL)
    return NULL;
  init_nodelist();

  /* Microdescriptors don't carry an identity digest, so we need to figure
   * it out by looking up the routerstatus. */
  rs = router_get_consensus_status_by_descriptor_digest(ns, md->digest);
  if (rs == NULL)
    return NULL;
  node = node_get_mutable_by_id(rs->identity_digest);
  if (node) {
    if (node->md)
      node->md->held_by_nodes--;
    node->md = md;
    md->held_by_nodes++