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
    md->held_by_nodes++;
  }
  return node;
}

/** Tell the nodelist that the current usable consensus is <b>ns</b>.
 * This makes the nodelist change all of the routerstatus entries for
 * the nodes, drop nodes that no longer have enough info to get used,
 * and grab microdescriptors into nodes as appropriate.
 */
void
nodelist_set_consensus(networkstatus_t *ns)
{
  const or_options_t *options = get_options();
  int authdir = authdir_mode_v3(options);
  int client = !server_mode(options);

  init_nodelist();
  if (ns->flavor == FLAV_MICRODESC)
    (void) get_microdesc_cache(); /* Make sure it exists first. */

  SMARTLIST_FOREACH(the_nodelist->nodes, node_t *, node,
                    node->rs = NULL);

  SMARTLIST_FOREACH_BEGIN(ns->routerstatus_list, routerstatus_t *, rs) {
    node_t *node = node_get_or_create(rs->identity_digest);
    node->rs = rs;
    if (ns->flavor == FLAV_MICRODESC) {
      if (node->md == NULL ||
          tor_memneq(node->md->digest,rs->descriptor_digest,DIGEST256_LEN)) {
        if (node->md)
          node->md->held_by_nodes--;
        node->md = microdesc_cache_lookup_by_digest256(NULL,
                                                       rs->descriptor_digest);
        if (node->md)
          node->md->held_by_nodes++;
      }
    }

    node_set_country(node);

    /* If we're not an authdir, believe others. */
    if (!authdir) {
      node->is_valid = rs->is_valid;
      node->is_running = rs->is_flagged_running;
      node->is_fast = rs->is_fast;
      node->is_stable = rs->is_stable;
      node->is_possible_guard = rs->is_possible_guard;
      node->is_exit = rs->is_exit;
      node->is_bad_directory = rs->is_bad_directory;
      node->is_bad_exit = rs->is_bad_exit;
      node->is_hs_dir = rs->is_hs_dir;
      node->ipv6_preferred = 0;
      if (client && options->ClientPreferIPv6ORPort == 1 &&
          (tor_addr_is_null(&rs->ipv6_addr) == 0 ||
           (node->md && tor_addr_is_null(&node->md->ipv6_addr) == 0)))
        node->ipv6_preferred = 1;
    }

  } SMARTLIST_FOREACH_END(rs);

  nodelist_purge();

  if (! authdir) {
    SMARTLIST_FOREACH_BEGIN(the_nodelist->nodes, node_t *, node) {
      /* We have no routerstatus for this router. Clear flags so we can skip
       * it, maybe.*/
      if (!node->rs) {
        tor_assert(node->ri); /* if it had only an md, or nothing, purge
                               * would have removed it. */
        if (node->ri->purpose == ROUTER_PURPOSE_GENERAL) {
          /* Clear all flags. */
          node->is_valid = node->is_running = node->is_hs_dir =
            node->is_fast = node->is_stable =
            node->is_possible_guard = node->is_exit =
            node->is_bad_exit = node->is_bad_directory =
            node->ipv6_preferred = 0;
        }
      }
    } SMARTLIST_FOREACH_END(node);
  }
}

/** Helper: return true iff a node has a usable amount of information*/
static INLINE int
node_is_usable(const node_t *node)
{
  return (node->rs) || (node->ri);
}

/** Tell the nodelist that <b>md</b> is no longer a microdescriptor for the
 * node with <b>identity_digest</b>. */
void
nodelist_remove_microdesc(const char *identity_digest, microdesc_t *md)
{
  node_t *node = node_get_mutable_by_id(identity_digest);
  if (node && node->md == md) {
    node->md = NULL;
    md->held_by_nodes--;
  }
}

/** Tell the nodelist that <b>ri</b> is no longer in the routerlist. */
void
nodelist_remove_routerinfo(routerinfo_t *ri)
{
  node_t *node = node_get_mutable_by_id(ri->cache_info.identity_digest);
  if (node && node->ri == ri) {
    node->ri = NULL;
    if (! node_is_usable(node)) {
      nodelist_drop_node(node, 1);
      node_free(node);
    }
  }
}

/** Remove <b>node</b> from the nodelist.  (Asserts that it was there to begin
 * with.) */
static void
nodelist_drop_node(node_t *node, int remove_from_ht)
{
  node_t *tmp;
  int idx;
  if (remove_from_ht) {
    tmp = HT_REMOVE(nodelist_map, &the_nodelist->nodes_by_id, node);
    tor_assert(tmp == node);
  }

  idx = node->nodelist_idx;
  tor_assert(idx >= 0);

  tor_assert(node == smartlist_get(the_nodelist->nodes, idx));
  smartlist_del(the_nodelist->nodes, idx);
  if (idx < smartlist_len(the_nodelist->nodes)) {
    tmp = smartlist_get(the_nodelist->nodes, idx);
    tmp->nodelist_idx = idx;
  }
  node->nodelist_idx = -1;
}

/** Release storage held by <b>node</b>  */
static void
node_free(node_t *node)
{
  if (!node)
    return;
  if (node->md)
    node->md->held_by_nodes--;
  tor_assert(node->nodelist_idx == -1);
  tor_free(node);
}

/** Remove all entries from the nodelist that don't have enough info to be
 * usable for anything. */
void
nodelist_purge(void)
{
  node_t **iter;
  if (PREDICT_UNLIKELY(the_nodelist == NULL))
    return;

  /* Remove the non-usable nodes. */
  for (iter = HT_START(nodelist_map, &the_nodelist->nodes_by_id); iter; ) {
    node_t *node = *iter;

    if (node->md && !node->rs) {
      /* An md is only useful if there is an rs. */
      node->md->held_by_nodes--;
      node->md = NULL;
    }

    if (node_is_usable(node)) {
      iter = HT_NEXT(nodelist_map, &the_nodelist->nodes_by_id, iter);
    } else {
      iter = HT_NEXT_RMV(nodelist_map, &the_nodelist->nodes_by_id, iter);
      nodelist_drop_node(node, 0);
      node_free(node);
    }
  }
  nodelist_assert_ok();
}

/** Release all storage held by the nodelist. */
void
nodelist_free_all(void)
{
  if (PREDICT_UNLIKELY(the_nodelist == NULL))
    return;

  HT_CLEAR(nodelist_map, &the_nodelist->nodes_by_id);
  SMARTLIST_FOREACH_BEGIN(the_nodelist->nodes, node_t *, node) {
    node->nodelist_idx = -1;
    node_free(node);
  } SMARTLIST_FOREACH_END(node);

  smartlist_free(the_nodelist->nodes);

  tor_free(the_nodelist);
}

/** Check that the nodelist is internally consistent, and consistent with
 * the directory info it's derived from.
 */
void
nodelist_assert_ok(void)
{
  routerlist_t *rl = router_get_routerlist();
  networkstatus_t *ns = networkstatus_get_latest_consensus();
  digestmap_t *dm;

  if (!the_nodelist)
    return;

  dm = digestmap_new();

  /* every routerinfo in rl->routers should be in the nodelist. */
  if (rl) {
    SMARTLIST_FOREACH_BEGIN(rl->routers, routerinfo_t *, ri) {
      const node_t *node = node_get_by_id(ri->cache_info.identity_digest);
      tor_assert(node && node->ri == ri);
      tor_assert(fast_memeq(ri->cache_info.identity_digest,
                             node->identity, DIGEST_LEN));
      tor_assert(! digestmap_get(dm, node->identity));
      digestmap_set(dm, node->identity, (void*)node);
    } SMARTLIST_FOREACH_END(ri);
  }

  /* every routerstatus in ns should be in the nodelist */
  if (ns) {
    SMARTLIST_FOREACH_BEGIN(ns->routerstatus_list, routerstatus_t *, rs) {
      const node_t *node = node_get_by_id(rs->identity_digest);
      tor_assert(node && node->rs == rs);
      tor_assert(fast_memeq(rs->identity_digest, node->identity, DIGEST_LEN));
      digestmap_set(dm, node->identity, (void*)node);
      if (ns->flavor == FLAV_MICRODESC) {
        /* If it's a microdesc consensus, every entry that has a
         * microdescriptor should be in the nodelist.
         */
        microdesc_t *md =
          microdesc_cache_lookup_by_digest256(NULL, rs->descriptor_digest);
        tor_assert(md == node->md);
        if (md)
          tor_assert(md->held_by_nodes >= 1);
      }
    } SMARTLIST_FOREACH_END(rs);
  }

  /* The nodelist should have no other entries, and its entries should be
   * well-formed. */
  SMARTLIST_FOREACH_BEGIN(the_nodelist->nodes, node_t *, node) {
    tor_assert(digestmap_get(dm, node->identity) != NULL);
    tor_assert(node_sl_idx == node->nodelist_idx);
  } SMARTLIST_FOREACH_END(node);

  tor_assert((long)smartlist_len(the_nodelist->nodes) ==
             (long)HT_SIZE(&the_nodelist->nodes_by_id));

  digestmap_free(dm, NULL);
}

/** Return a list of a node_t * for every node we know about.  The caller
 * MUST NOT modify the list. (You can set and clear flags in the nodes if
 * you must, but you must not add or remove nodes.) */
smartlist_t *
nodelist_get_list(void)
{
  init_nodelist();
  return the_nodelist->nodes;
}

/** Given a hex-encoded nickname of the format DIGEST, $DIGEST, $DIGEST=name,
 * or $DIGEST~name, return the node with the matching identity digest and
 * nickname (if any).  Return NULL if no such node exists, or if <b>hex_id</b>
 * is not well-formed. */
const node_t *
node_get_by_hex_id(const char *hex_id)
{
  char digest_buf[DIGEST_LEN];
  char nn_buf[MAX_NICKNAME_LEN+1];
  char nn_char='\0';

  if (hex_digest_nickname_decode(hex_id, digest_buf, &nn_char, nn_buf)==0) {
    const node_t *node = node_get_by_id(digest_buf);
    if (!node)
      return NULL;
    if (nn_char) {
      const char *real_name = node_get_nickname(node);
      if (!real_name || strcasecmp(real_name, nn_buf))
        return NULL;
      if (nn_char == '=') {
        const char *named_id =
          networkstatus_get_router_digest_by_nickname(nn_buf);
        if (!named_id || tor_memneq(named_id, digest_buf, DIGEST_LEN))
          return NULL;
      }
    }
    return node;
  }

  return NULL;
}

/** Given a nickname (possibly verbose, possibly a hexadecimal digest), return
 * the corresponding node_t, or NULL if none exists.  Warn the user if
 * <b>warn_if_unnamed</b> is set, and they have specified a router by
 * nickname, but the Named flag isn't set for that router. */
const node_t *
node_get_by_nickname(const char *nickname, int warn_if_unnamed)
{
 