/* * Copyright (c) 2012-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitmux_ewma.c
 * \brief EWMA circuit selection as a circuitmux_t policy
 **/

#define TOR_CIRCUITMUX_EWMA_C_

#include <math.h>

#include "or.h"
#include "circuitmux.h"
#include "circuitmux_ewma.h"
#include "networkstatus.h"

/*** EWMA parameter #defines ***/

/** How long does a tick last (seconds)? */
#define EWMA_TICK_LEN 10

/** The default per-tick scale factor, if it hasn't been overridden by a
 * consensus or a configuration setting.  zero means "disabled". */
#define EWMA_DEFAULT_HALFLIFE 0.0

/*** Some useful constant #defines ***/

/*DOCDOC*/
#define EPSILON 0.00001
/*DOCDOC*/
#define LOG_ONEHALF -0.69314718055994529

/*** EWMA structures ***/

typedef struct cell_ewma_s cell_ewma_t;
typedef struct ewma_policy_data_s ewma_policy_data_t;
typedef struct ewma_policy_circ_data_s ewma_policy_circ_data_t;

/**
 * The cell_ewma_t structure keeps track of how many cells a circuit has
 * transferred recently.  It keeps an EWMA (exponentially weighted moving
 * average) of the number of cells flushed from the circuit queue onto a
 * connection in channel_flush_from_first_active_circuit().
 */

struct cell_ewma_s {
  /** The last 'tick' at which we recalibrated cell_count.
   *
   * A cell sent at exactly the start of this tick has weight 1.0. Cells sent
   * since the start of this tick have weight greater than 1.0; ones sent
   * earlier have less weight. */
  unsigned int last_adjusted_tick;
  /** The EWMA of the cell count. */
  double cell_count;
  /** True iff this is the cell count for a circuit's previous
   * channel. */
  unsigned int is_for_p_chan : 1;
  /** The position of the circuit within the OR connection's priority
   * queue. */
  int heap_index;
};

struct ewma_policy_data_s {
  circuitmux_policy_data_t base_;

  /**
   * Priority queue of cell_ewma_t for circuits with queued cells waiting
   * for room to free up on the channel that owns this circuitmux.  Kept
   * in heap order according to EWMA.  This was formerly in channel_t, and
   * in or_connection_t before that.
   */
  smartlist_t *active_circuit_pqueue;

  /**
   * The tick on which the cell_ewma_ts in active_circuit_pqueue last had
   * their ewma values rescaled.  This was formerly in channel_t, and in
   * or_connection_t before that.
   */
  unsigned int active_circuit_pqueue_last_recalibrated;
};

struct ewma_policy_circ_data_s {
  circuitmux_policy_circ_data_t base_;

  /**
   * The EWMA count for the number of cells flushed from this circuit
   * onto this circuitmux.  Used to determine which circuit to flush
   * from next.  This was formerly in circuit_t and or_circuit_t.
   */
  cell_ewma_t cell_ewma;

  /**
   * Pointer back to the circuit_t this is for; since we're separating
   * out circuit selection policy like this, we can't attach cell_ewma_t
   * to the circuit_t any more, so we can't use SUBTYPE_P directly to a
   * circuit_t like before; instead get it here.
   */
  circuit_t *circ;
};

#define EWMA_POL_DATA_MAGIC 0x2fd8b16aU
#define EWMA_POL_CIRC_DATA_MAGIC 0x761e7747U

/*** Downcasts for the above types ***/

static ewma_policy_data_t *
TO_EWMA_POL_DATA(circuitmux_policy_data_t *);

static ewma_policy_circ_data_t *
TO_EWMA_POL_CIRC_DATA(circuitmux_policy_circ_data_t *);

/**
 * Downcast a circuitmux_policy_data_t to an ewma_policy_data_t and assert
 * if the cast is impossible.
 */

static INLINE ewma_policy_data_t *
TO_EWMA_POL_DATA(circuitmux_policy_data_t *pol)
{
  if (!pol) return NULL;
  else {
    tor_assert(pol->magic == EWMA_POL_DATA_MAGIC);
    return DOWNCAST(ewma_policy_data_t, pol);
  }
}

/**
 * Downcast a circuitmux_policy_circ_data_t to an ewma_policy_circ_data_t
 * and assert if the cast is impossible.
 */

static INLINE ewma_policy_circ_data_t *
TO_EWMA_POL_CIRC_DATA(circuitmux_policy_circ_data_t *pol)
{
  if (!pol) return NULL;
  else {
    tor_assert(pol->magic == EWMA_POL_CIRC_DATA_MAGIC);
    return DOWNCAST(ewma_policy_circ_data_t, pol);
  }
}

/*** Static declarations for circuitmux_ewma.c ***/

static void add_cell_ewma(ewma_policy_data_t *pol, cell_ewma_t *ewma);
static int compare_cell_ewma_counts(const void *p1, const void *p2);
static unsigned cell_ewma_tick_from_timeval(const struct timeval *now,
                                            double *remainder_out);
static circuit_t * cell_ewma_to_circuit(cell_ewma_t *ewma);
static INLINE double get_scale_factor(unsigned from_tick, unsigned to_tick);
static cell_ewma_t * pop_first_cell_ewma(ewma_policy_data_t *pol);
static void remove_cell_ewma(ewma_policy_data_t *pol, cell_ewma_t *ewma);
static void scale_single_cell_ewma(cell_ewma_t *ewma, unsigned cur_tick);
static void scale_active_circuits(ewma_policy_data_t *pol,
                                  unsigned cur_tick);

/*** Circuitmux policy methods ***/

static circuitmux_policy_data_t * ewma_alloc_cmux_data(circuitmux_t *cmux);
static void ewma_free_cmux_data(circuitmux_t *cmux,
                                circuitmux_policy_data_t *pol_data);
static circuitmux_policy_circ_data_t *
ewma_alloc_circ_data(circuitmux_t *cmux, circuitmux_policy_data_t *pol_data,
                     circuit_t *circ, cell_direction_t direction,
                     unsigned int cell_count);
static void
ewma_free_circ_data(circuitmux_t *cmux,
                    circuitmux_policy_data_t *pol_data,
                    circuit_t *circ,
                    circuitmux_policy_circ_data_t *pol_circ_data);
static void
ewma_notify_circ_active(circuitmux_t *cmux,
                        circuitmux_policy_data_t *pol_data,
                        circuit_t *circ,
                        circuitmux_policy_circ_data_t *pol_circ_data);
static void
ewma_notify_circ_inactive(circuitmux_t *cmux,
                          circuitmux_policy_data_t *pol_data,
                          circuit_t *circ,
                          circuitmux_policy_circ_data_t *pol_circ_data);
static void
ewma_notify_xmit_cells(circuitmux_t *cmux,
                       circuitmux_policy_data_t *pol_data,
                       circuit_t *circ,
                       circuitmux_policy_circ_data_t *pol_circ_data,
                       unsigned int n_cells);
static circuit_t *
ewma_pick_active_circuit(circuitmux_t *cmux,
                         circuitmux_policy_data_t *pol_data);

/*** EWMA global variables ***/

/** The per-tick scale factor to be used when computing cell-count EWMA
 * values.  (A cell sent N ticks before the start of the current tick
 * has value ewma_scale_factor ** N.)
 */
static double ewma_scale_factor = 0.1;
/* DOCDOC ewma_enabled */
static int ewma_enabled = 0;

/*** EWMA circuitmux_policy_t method table ***/

circuitmux_policy_t ewma_policy = {
  /*.alloc_cmux_data =*/ ewma_alloc_cmux_data,
  /*.free_cmux_data =*/ ewma_free_cmux_data,
  /*.alloc_circ_data =*/ ewma_alloc_circ_data,
  /*.free_circ_data =*/ ewma_free_circ_data,
  /*.notify_circ_active =*/ ewma_notify_circ_active,
  /*.notify_circ_inactive =*/ ewma_notify_circ_inactive,
  /*.notify_set_n_cells =*/ NULL, /* EWMA doesn't need this */
  