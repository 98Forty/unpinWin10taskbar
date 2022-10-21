
/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rephist.c
 * \brief Basic history and "reputation" functionality to remember
 *    which servers have worked in the past, how much bandwidth we've
 *    been using, which ports we tend to want, and so on; further,
 *    exit port statistics, cell statistics, and connection statistics.
 **/

#include "or.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "config.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "rephist.h"
#include "router.h"
#include "routerlist.h"
#include "ht.h"

static void bw_arrays_init(void);
static void predicted_ports_init(void);

/** Total number of bytes currently allocated in fields used by rephist.c. */
uint64_t rephist_total_alloc=0;
/** Number of or_history_t objects currently allocated. */
uint32_t rephist_total_num=0;

/** If the total weighted run count of all runs for a router ever falls
 * below this amount, the router can be treated as having 0 MTBF. */
#define STABILITY_EPSILON   0.0001
/** Value by which to discount all old intervals for MTBF purposes.  This
 * is compounded every STABILITY_INTERVAL. */
#define STABILITY_ALPHA     0.95
/** Interval at which to discount all old intervals for MTBF purposes. */
#define STABILITY_INTERVAL  (12*60*60)
/* (This combination of ALPHA, INTERVAL, and EPSILON makes it so that an
 * interval that just ended counts twice as much as one that ended a week ago,
 * 20X as much as one that ended a month ago, and routers that have had no
 * uptime data for about half a year will get forgotten.) */

/** History of an OR-\>OR link. */
typedef struct link_history_t {
  /** When did we start tracking this list? */
  time_t since;
  /** When did we most recently note a change to this link */
  time_t changed;
  /** How many times did extending from OR1 to OR2 succeed? */
  unsigned long n_extend_ok;
  /** How many times did extending from OR1 to OR2 fail? */
  unsigned long n_extend_fail;
} link_history_t;

/** History of an OR. */
typedef struct or_history_t {
  /** When did we start tracking this OR? */
  time_t since;
  /** When did we most recently note a change to this OR? */
  time_t changed;
  /** How many times did we successfully connect? */
  unsigned long n_conn_ok;
  /** How many times did we try to connect and fail?*/
  unsigned long n_conn_fail;
  /** How many seconds have we been connected to this OR before
   * 'up_since'? */
  unsigned long uptime;
  /** How many seconds have we been unable to connect to this OR before
   * 'down_since'? */
  unsigned long downtime;
  /** If nonzero, we have been connected since this time. */
  time_t up_since;
  /** If nonzero, we have been unable to connect since this time. */
  time_t down_since;

  /** The address at which we most recently connected to this OR
   * successfully. */
  tor_addr_t last_reached_addr;

  /** The port at which we most recently connected to this OR successfully */
  uint16_t last_reached_port;

  /* === For MTBF tracking: */
  /** Weighted sum total of all times that this router has been online.
   */
  unsigned long weighted_run_length;
  /** If the router is now online (according to stability-checking rules),
   * when did it come online? */
  time_t start_of_run;
  /** Sum of weights for runs in weighted_run_length. */
  double total_run_weights;
  /* === For fractional uptime tracking: */
  time_t start_of_downtime;
  unsigned long weighted_uptime;
  unsigned long total_weighted_time;

  /** Map from hex OR2 identity digest to a link_history_t for the link
   * from this OR to OR2. */
  digestmap_t *link_history_map;
} or_history_t;

/** When did we last multiply all routers' weighted_run_length and
 * total_run_weights by STABILITY_ALPHA? */
static time_t stability_last_downrated = 0;

/**  */
static time_t started_tracking_stability = 0;

/** Map from hex OR identity digest to or_history_t. */
static digestmap_t *history_map = NULL;

/** Return the or_history_t for the OR with identity digest <b>id</b>,
 * creating it if necessary. */
static or_history_t *
get_or_history(const char* id)
{
  or_history_t *hist;

  if (tor_digest_is_zero(id))
    return NULL;

  hist = digestmap_get(history_map, id);
  if (!hist) {
    hist = tor_malloc_zero(sizeof(or_history_t));
    rephist_total_alloc += sizeof(or_history_t);
    rephist_total_num++;
    hist->link_history_map = digestmap_new();
    hist->since = hist->changed = time(NULL);
    tor_addr_make_unspec(&hist->last_reached_addr);
    digestmap_set(history_map, id, hist);
  }
  return hist;
}

/** Return the link_history_t for the link from the first named OR to
 * the second, creating it if necessary. (ORs are identified by
 * identity digest.)
 */
static link_history_t *
get_link_history(const char *from_id, const char *to_id)
{
  or_history_t *orhist;
  link_history_t *lhist;
  orhist = get_or_history(from_id);
  if (!orhist)
    return NULL;
  if (tor_digest_is_zero(to_id))
    return NULL;
  lhist = (link_history_t*) digestmap_get(orhist->link_history_map, to_id);
  if (!lhist) {
    lhist = tor_malloc_zero(sizeof(link_history_t));
    rephist_total_alloc += sizeof(link_history_t);
    lhist->since = lhist->changed = time(NULL);
    digestmap_set(orhist->link_history_map, to_id, lhist);
  }
  return lhist;
}

/** Helper: free storage held by a single link history entry. */
static void
free_link_history_(void *val)
{
  rephist_total_alloc -= sizeof(link_history_t);
  tor_free(val);
}

/** Helper: free storage held by a single OR history entry. */
static void
free_or_history(void *_hist)
{
  or_history_t *hist = _hist;
  digestmap_free(hist->link_history_map, free_link_history_);
  rephist_total_alloc -= sizeof(or_history_t);
  rephist_total_num--;
  tor_free(hist);
}

/** Update an or_history_t object <b>hist</b> so that its uptime/downtime
 * count is up-to-date as of <b>when</b>.
 */
static void
update_or_history(or_history_t *hist, time_t when)
{
  tor_assert(hist);
  if (hist->up_since) {
    tor_assert(!hist->down_since);
    hist->uptime += (when - hist->up_since);
    hist->up_since = when;
  } else if (hist->down_since) {
    hist->downtime += (when - hist->down_since);
    hist->down_since = when;
  }
}

/** Initialize the static data structures for tracking history. */
void
rep_hist_init(void)
{
  history_map = digestmap_new();
  bw_arrays_init();
  predicted_ports_init();
}

/** Helper: note that we are no longer connected to the router with history
 * <b>hist</b>.  If <b>failed</b>, the connection failed; otherwise, it was
 * closed correctly. */
static void
mark_or_down(or_history_t *hist, time_t when, int failed)
{
  if (hist->up_since) {