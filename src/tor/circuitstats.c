/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CIRCUITSTATS_PRIVATE

#include "or.h"
#include "circuitbuild.h"
#include "circuitstats.h"
#include "config.h"
#include "confparse.h"
#include "control.h"
#include "networkstatus.h"
#include "statefile.h"

#undef log
#include <math.h>

static void cbt_control_event_buildtimeout_set(
                                  const circuit_build_times_t *cbt,
                                  buildtimeout_set_event_t type);

#define CBT_BIN_TO_MS(bin) ((bin)*CBT_BIN_WIDTH + (CBT_BIN_WIDTH/2))

/** Global list of circuit build times */
// XXXX: Add this as a member for entry_guard_t instead of global?
// Then we could do per-guard statistics, as guards are likely to
// vary in their own latency. The downside of this is that guards
// can change frequently, so we'd be building a lot more circuits
// most likely.
static circuit_build_times_t circ_times;

#ifdef TOR_UNIT_TESTS
/** If set, we're running the unit tests: we should avoid clobbering
 * our state file or accessing get_options() or get_or_state() */
static int unit_tests = 0;
#else
#define unit_tests 0
#endif

/** Return a pointer to the data structure describing our current circuit
 * build time history and computations. */
const circuit_build_times_t *
get_circuit_build_times(void)
{
  return &circ_times;
}

/** As get_circuit_build_times, but return a mutable pointer. */
circuit_build_times_t *
get_circuit_build_times_mutable(void)
{
  return &circ_times;
}

/** Return the time to wait before actually closing an under-construction, in
 * milliseconds. */
double
get_circuit_build_close_time_ms(void)
{
  return circ_times.close_ms;
}

/** Return the time to wait before giving up on an under-construction circuit,
 * in milliseconds. */
double
get_circuit_build_timeout_ms(void)
{
  return circ_times.timeout_ms;
}

/**
 * This function decides if CBT learning should be disabled. It returns
 * true if one or more of the following four conditions are met:
 *
 *  1. If the cbtdisabled consensus parameter is set.
 *  2. If the torrc option LearnCircuitBuildTimeout is false.
 *  3. If we are a directory authority
 *  4. If we fail to write circuit build time history to our state file.
 */
int
circuit_build_times_disabled(void)
{
  if (unit_tests) {
    return 0;
  } else {
    int consensus_disabled = networkstatus_get_param(NULL, "cbtdisabled",
                                                     0, 0, 1);
    int config_disabled = !get_options()->LearnCircuitBuildTimeout;
    int dirauth_disabled = get_options()->AuthoritativeDir;
    int state_disabled = did_last_state_file_write_fail() ? 1 : 0;

    if (consensus_disabled || config_disabled || dirauth_disabled ||
           state_disabled) {
      log_debug(LD_CIRC,
               "CircuitBuildTime learning is disabled. "
               "Consensus=%d, Config=%d, AuthDir=%d, StateFile=%d",
               consensus_disabled, config_disabled, dirauth_disabled,
               state_disabled);
      return 1;
    } else {
      log_debug(LD_CIRC,
                "CircuitBuildTime learning is not disabled. "
                "Consensus=%d, Config=%d, AuthDir=%d, StateFile=%d",
                consensus_disabled, config_disabled, dirauth_disabled,
                state_disabled);
      return 0;
    }
  }
}

/**
 * Retrieve and bounds-check the cbtmaxtimeouts consensus paramter.
 *
 * Effect: When this many timeouts happen in the last 'cbtrecentcount'
 * circuit attempts, the client should discard all of its history and
 * begin learning a fresh timeout value.
 */
static int32_t
circuit_build_times_max_timeouts(void)
{
  int32_t cbt_maxtimeouts;

  cbt_maxtimeouts = networkstatus_get_param(NULL, "cbtmaxtimeouts",
                                 CBT_DEFAULT_MAX_RECENT_TIMEOUT_COUNT,
                                 CBT_MIN_MAX_RECENT_TIMEOUT_COUNT,
                                 CBT_MAX_MAX_RECENT_TIMEOUT_COUNT);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_max_timeouts() called, cbtmaxtimeouts is"
              " %d",
              cbt_maxtimeouts);
  }

  return cbt_maxtimeouts;
}

/**
 * Retrieve and bounds-check the cbtnummodes consensus paramter.
 *
 * Effect: This value governs how many modes to use in the weighted
 * average calculation of Pareto parameter Xm. A value of 3 introduces
 * some bias (2-5% of CDF) under ideal conditions, but allows for better
 * performance in the event that a client chooses guard nodes of radically
 * different performance characteristics.
 */
static int32_t
circuit_build_times_default_num_xm_modes(void)
{
  int32_t num = networkstatus_get_param(NULL, "cbtnummodes",
                                        CBT_DEFAULT_NUM_XM_MODES,
                                        CBT_MIN_NUM_XM_MODES,
                                        CBT_MAX_NUM_XM_MODES);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_default_num_xm_modes() called, cbtnummodes"
              " is %d",
              num);
  }

  return num;
}

/**
 * Retrieve and bounds-check the cbtmincircs consensus paramter.
 *
 * Effect: This is the minimum number of circuits to build before
 * computing a timeout.
 */
static int32_t
circuit_build_times_min_circs_to_observe(void)
{
  int32_t num = networkstatus_get_param(NULL, "cbtmincircs",
                                        CBT_DEFAULT_MIN_CIRCUITS_TO_OBSERVE,
                                        CBT_MIN_MIN_CIRCUITS_TO_OBSERVE,
                                        CBT_MAX_MIN_CIRCUITS_TO_OBSERVE);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_min_circs_to_observe() called, cbtmincircs"
              " is %d",
              num);
  }

  return num;
}

/** Return true iff <b>cbt</b> has recorded enough build times that we
 * want to start acting on the timeout it implies. */
int
circuit_build_times_enough_to_compute(const circuit_build_times_t *cbt)
{
  return cbt->total_build_times >= circuit_build_times_min_circs_to_observe();
}

/**
 * Retrieve and bounds-check the cbtquantile consensus paramter.
 *
 * Effect: This is the position on the quantile curve to use to set the
 * timeout value. It is a percent (10-99).
 */
double
circuit_build_times_quantile_cutoff(void)
{
  int32_t num = networkstatus_get_param(NULL, "cbtquantile",
                                        CBT_DEFAULT_QUANTILE_CUTOFF,
                                        CBT_MIN_QUANTILE_CUTOFF,
                                        CBT_MAX_QUANTILE_CUTOFF);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_quantile_cutoff() called, cbtquantile"
              " is %d",
              num);
  }

  return num/100.0;
}

/**
 * Retrieve and bounds-check the cbtclosequantile consensus paramter.
 *
 * Effect: This is the position on the quantile curve to use to set the
 * timeout value to use to actually close circuits. It is a percent
 * (0-99).
 */
static double
circuit_build_times_close_quantile(void)
{
  int32_t param;
  /* Cast is safe - circuit_build_times_quantile_cutoff() is capped */
  int32_t min = (int)tor_lround(100*circuit_build_times_quantile_cutoff());
  param = networkstatus_get_param(NULL, "cbtclosequantile",
             CBT_DEFAULT_CLOSE_QUANTILE,
             CBT_MIN_CLOSE_QUANTILE,
             CBT_MAX_CLOSE_QUANTILE);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_close_quantile() called, cbtclosequantile"
              " is %d", param);
  }

  if (param < min) {
    log_warn(LD_DIR, "Consensus parameter cbtclosequantile is "
             "too small, raising to %d", min);
    param = min;
  }
  return param / 100.0;
}

/**
 * Retrieve and bounds-check the cbttestfreq consensus paramter.
 *
 * Effect: Describes how often in seconds to build a test circuit to
 * gather timeout values. Only applies if less than 'cbtmincircs'
 * have been recorded.
 */
static int32_t
circuit_build_times_test_frequency(void)
{
  int32_t num = networkstatus_get_param(NULL, "cbttestfreq",
                                        CBT_DEFAULT_TEST_FREQUENCY,
                                        CBT_MIN_TEST_FREQUENCY,
                                        CBT_MAX_TEST_FREQUENCY);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_test_frequency() called, cbttestfreq is %d",
              num);
  }

  return num;
}

/**
 * Retrieve and bounds-check the cbtmintimeout consensus parameter.
 *
 * Effect: This is the minimum allowed timeout value in milliseconds.
 * The minimum is to prevent rounding to 0 (we only check once
 * per second).
 */
static int32_t
circuit_build_times_min_timeout(void)
{
  int32_t num = networkstatus_get_param(NULL, "cbtmintimeout",
                                        CBT_DEFAULT_TIMEOUT_MIN_VALUE,
                                        CBT_MIN_TIMEOUT_MIN_VALUE,
                                        CBT_MAX_TIMEOUT_MIN_VALUE);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_min_timeout() called, cbtmintimeout is %d",
              num);
  }

  return num;
}

/**
 * Retrieve and bounds-check the cbtinitialtimeout consensus paramter.
 *
 * Effect: This is the timeout value to use before computing a timeout,
 * in milliseconds.
 */
int32_t
circuit_build_times_initial_timeout(void)
{
  int32_t min = circuit_build_times_min_timeout();
  int32_t param = networkstatus_get_param(NULL, "cbtinitialtimeout",
                                          CBT_DEFAULT_TIMEOUT_INITIAL_VALUE,
                                          CBT_MIN_TIMEOUT_INITIAL_VALUE,
                                          CBT_MAX_TIMEOUT_INITIAL_VALUE);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_initial_timeout() called, "
              "cbtinitialtimeout is %d",
              param);
  }

  if (param < min) {
    log_warn(LD_DIR, "Consensus parameter cbtinitialtimeout is too small, "
             "raising to %d", min);
    param = min;
  }
  return param;
}

/**
 * Retrieve and bounds-check the cbtrecentcount consensus paramter.
 *
 * Effect: This is the number of circuit build times to keep track of
 * for deciding if we hit cbtmaxtimeouts and need to reset our state
 * and learn a new timeout.
 */
static int32_t
circuit_build_times_recent_circuit_count(networkstatus_t *ns)
{
  int32_t num;
  num = networkstatus_get_param(ns, "cbtrecentcount",
                                CBT_DEFAULT_RECENT_CIRCUITS,
                                CBT_MIN_RECENT_CIRCUITS,
                                CBT_MAX_RECENT_CIRCUITS);

  if (!(get_options()->LearnCircuitBuildTimeout)) {
    log_debug(LD_BUG,
              "circuit_build_times_recent_circuit_count() called, "
              "cbtrecentcount is %d",
              num);
  }

  return num;
}

/**
 * This function is called when we get a consensus update.
 *
 * It checks to see if we have changed any consensus parameters
 * that require reallocation or discard of previous stats.
 */
void
circuit_build_times_new_consensus_params(circuit_build_times_t *cbt,
                                         networkstatus_t *ns)
{
  int32_t num;

  /*
   * First check if we're doing adaptive timeouts at all; nothing to
   * update if we aren't.
   */

  if (!circuit_build_times_disabled()) {
    num = circuit_build_times_recent_circuit_count(ns);

    if (num > 0) {
      if (num != cbt->liveness.num_recent_circs) {
        int8_t *recent_circs;
        log_notice(LD_CIRC, "The Tor Directory Consensus has changed how many "
                   "circuits we must track to detect network failures from %d "
                   "to %d.", cbt->liveness.num_recent_circs, num);

        tor_assert(cbt->liveness.timeouts_after_firsthop ||
                   cbt->liveness.num_recent_circs == 0);

        /*
         * Technically this is a circular array that we are reallocating
         * and memcopying. However, since it only consists of either 1s
         * or 0s, and is only used in a statistical test to determine when
         * we should discard our history after a sufficient number of 1's
         * have been reached, it is fine if order is not preserved or
         * elements are lost.
         *
         * cbtrecentcount should only be changing in cases of severe network
         * distress anyway, so memory correctness here is paramount over
         * doing acrobatics to preserve the array.
         */
        recent_circs = tor_malloc_zero(sizeof(int8_t)*num);
        if (cbt->liveness.timeouts_after_firsthop &&
            cbt->liveness.num_recent_circs > 0) {
          memcpy(recent_circs, cbt->liveness.timeouts_after_firsthop,
                 sizeof(int8_t)*MIN(num, cbt->liveness.num_recent_circs));
        }

        // Adjust the index if it needs it.
        if (num < cbt->liveness.num_recent_circs) {
          cbt->liveness.after_firsthop_idx = MIN(num-1,
                  cbt->liveness.after_firsthop_idx);
        }

        tor_free(cbt->liveness.timeouts_after_firsthop);
        cbt->liveness.timeouts_after_firsthop = recent_circs;
        cbt->liveness.num_recent_circs = num;
      }
      /* else no change, nothing to do */
    } else { /* num == 0 */
      /*
       * Weird.  This probably shouldn't happen, so log a warning, but try
       * to do something sensible anyway.
       */

      log_warn(LD_CIRC,
               "The cbtrecentcircs consensus parameter came back zero!  "
               "This disables adaptive timeouts since we can't keep track of "
               "any recent circuits.");

      circuit_build_times_free_timeouts(cbt);
    }
  } else {
    /*
     * Adaptive timeouts are disabled; this might be because of the
     * LearnCircuitBuildTimes config parameter, and hence permanent, or
     * the cbtdisabled consensus parameter, so it may be a new condition.
     * Treat it like getting num == 0 above and free the circuit history
     * if we have any.
     */

    circuit_build_times_free_timeouts(cbt);
  }
}

/**
 * Return the initial default or configured timeout in milliseconds
 */
static double
circuit_build_times_get_initial_timeout(void)
{
  double timeout;

  /*
   * Check if we have LearnCircuitBuildTimeout, and if we don't,
   * always use CircuitBuildTimeout, no questions asked.
   */
  if (!unit_tests && get_options()->CircuitBuildTimeout) {
    timeout = get_options()->CircuitBuildTimeout*1000;
    if (get_options()->LearnCircuitBuildTimeout &&
        timeout < circuit_build_times_min_timeout()) {
      log_warn(LD_CIRC, "Config CircuitBuildTimeout too low. Setting to %ds",
               circuit_build_times_min_timeout()/1000);
      timeout = circuit_build_times_min_timeout();
    }
  } else {
    timeout = circuit_build_times_initial_timeout();
  }

  return timeout;
}

/**
 * Reset the build time state.
 *
 * Leave estimated parameters, timeout and network liveness intact
 * for future use.
 */
STATIC void
circuit_build_times_reset(circuit_build_times_t *cbt)
{
  memset(cbt->circuit_build_times, 0, sizeof(cbt->circuit_build_times));
  cbt->total_build_times = 0;
  cbt->build_times_idx = 0;
  cbt->have_computed_timeout = 0;
}

/**
 * Initialize the buildtimes structure for first use.
 *
 * Sets the initial timeout values based on either the config setting,
 * the consensus param, or the default (CBT_DEFAULT_TIMEOUT_INITIAL_VALUE).
 */
void
circuit_build_times_init(circuit_build_times_t *cbt)
{
  memset(cbt, 0, sizeof(*cbt));
  /*
   * Check if we really are using adaptive timeouts, and don't keep
   * track of this stuff if not.
   */
  if (!circuit_build_times_disabled()) {
    cbt->liveness.num_recent_circs =
      circuit_build_times_recent_circuit_count(NULL);
    cbt->liveness.timeouts_after_firsthop =
      tor_malloc_zero(sizeof(int8_t)*cbt->liveness.num_recent_circs);
  } else {
    cbt->liveness.num_recent_circs = 0;
    cbt->liveness.timeouts_after_firsthop = NULL;
  }
  cbt->close_ms = cbt->timeout_ms = circuit_build_times_get_initial_timeout();
  cbt_control_event_buildtimeout_set(cbt, BUILDTIMEOUT_SET_EVENT_RESET);
}

/**
 * Free the saved timeouts, if the cbtdisabled consensus parameter got turned
 * on or something.
 */

void
circuit_build_times_free_timeouts(circuit_build_times_t *cbt)
{
  if (!cbt) return;

  if (cbt->liveness.timeouts_after_firsthop) {
    tor_free(cbt->liveness.timeouts_after_firsthop);
  }

  cbt->liveness.num_recent_circs = 0;
}

#if 0
/**
 * Rewind our build time history by n positions.
 */
static void
circuit_build_times_rewind_history(circuit_build_times_t *cbt, int n)
{
  int i = 0;

  cbt->build_times_idx -= n;
  cbt->build_times_idx %= CBT_NCIRCUITS_TO_OBSERVE;

  for (i = 0; i < n; i++) {
    cbt->circuit_build_times[(i+cbt->build_times_idx)
                             %CBT_NCIRCUITS_TO_OBSERVE]=0;
  }

  if (cbt->total_build_times > n) {
    cbt->total_build_times -= n;
  } else {
    cbt->total_build_times = 0;
  }

  log_info(LD_CIRC,
          "Rewound history by %d places. Current index: %d. "
          "Total: %d", n, cbt->build_times_idx, cbt->total_build_times);
}
#endif

/**
 * Add a new build time value <b>time</b> to the set of build times. Time
 * units are milliseconds.
 *
 * circuit_build_times <b>cbt</b> is a circular array, so loop around when
 * array is full.
 */
int
circuit_build_times_add_time(circuit_build_times_t *cbt, build_time_t time)
{
  if (time <= 0 || time > CBT_BUILD_TIME_MAX) {
    log_warn(LD_BUG, "Circuit build time is too large (%u)."
                      "This is probably a bug.", time);
    tor_fragile_assert();
    return -1;
  }

  log_debug(LD_CIRC, "Adding circuit build time %u", time);

  cbt->circuit_build_times[cbt->build_times_idx] = time;
  cbt->build_times_idx = (cbt->build_times_idx + 1) % CBT_NCIRCUITS_TO_OBSERVE;
  if (cbt->total_build_times < CBT_NCIRCUITS_TO_OBSERVE)
    cbt->total_build_times++;

  if ((cbt->total_build_times % CBT_SAVE_STATE_EVERY) == 0) {
    /* Save state every n circuit builds */
    if (!unit_tests && !get_options()->AvoidDiskWrites)
      or_state_mark_dirty(get_or_state(), 0);
  }

  return 0;
}

/**
 * Return maximum circuit build time
 */
static build_time_t
circuit_build_times_max(const circuit_build_times_t *cbt)
{
  int i = 0;
  build_time_t max_build_time = 0;
  for (i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; i++) {
    if (cbt->circuit_build_times[i] > max_build_time
            && cbt->circuit_build_times[i] != CBT_BUILD_ABANDONED)
      max_build_time = cbt->circuit_build_times[i];
  }
  return max_build_time;
}

#if 0
/** Return minimum circuit build time */
build_time_t
circuit_build_times_min(circuit_build_times_t *cbt)
{
  int i = 0;
  build_time_t min_build_time = CBT_BUILD_TIME_MAX;
  for (i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; i++) {
    if (cbt->circuit_build_times[i] && /* 0 <-> uninitialized */
        cbt->circuit_build_times[i] < min_build_time)
      min_build_time = cbt->circuit_build_times[i];
  }
  if (min_build_time == CBT_BUILD_TIME_MAX) {
    log_warn(LD_CIRC, "No build times less than CBT_BUILD_TIME_MAX!");
  }
  return min_build_time;
}
#endif

/**
 * Calculate and return a histogram for the set of build times.
 *
 * Returns an allocated array of histrogram bins representing
 * the frequency of index*CBT_BIN_WIDTH millisecond
 * build times. Also outputs the number of bins in nbins.
 *
 * The return value must be freed by the caller.
 */
static uint32_t *
circuit_build_times_create_histogram(const circuit_build_times_t *cbt,
                                     build_time_t *nbins)
{
  uint32_t *histogram;
  build_time_t max_build_time = circuit_build_times_max(cbt);
  int i, c;

  *nbins = 1 + (max_build_time / CBT_BIN_WIDTH);
  histogram = tor_malloc_zero(*nbins * sizeof(build_time_t));

  // calculate histogram
  for (i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; i++) {
    if (cbt->circuit_build_times[i] == 0
            || cbt->circuit_build_times[i] == CBT_BUILD_ABANDONED)
      continue; /* 0 <-> uninitialized */

    c = (cbt->circuit_build_times[i] / CBT_BIN_WIDTH);
    histogram[c]++;
  }

  return histogram;
}

/**
 * Return the Pareto start-of-curve parameter Xm.
 *
 * Because we are not a true Pareto curve, we compute this as the
 * weighted average of the N most frequent build time bins. N is either
 * 1 if we don't have enough circuit build time data collected, or
 * determined by the consensus parameter cbtnummodes (default 3).
 */
static build_time_t
circuit_build_times_get_xm(circuit_build_times_t *cbt)
{
  build_time_t i, nbins;
  build_time_t *nth_max_bin;
  int32_t bin_counts=0;
  build_time_t ret = 0;
  uint32_t *histogram = circuit_build_times_create_histogram(cbt, &nbins);
  int n=0;
  int num_modes = circuit_build_times_default_num_xm_modes();

  tor_assert(nbins > 0);
  tor_assert(num_modes > 0);

  // Only use one mode if < 1000 buildtimes. Not enough data
  // for multiple.
  if (cbt->total_build_times < CBT_NCIRCUITS_TO_OBSERVE)
    num_modes = 1;

  nth_max_bin = (build_time_t*)tor_malloc_zero(num_modes*sizeof(build_time_t));

  /* Determine the N most common build times */
  for (i = 0; i < nbins; i++) {
    if (histogram[i] >= histogram[nth_max_bin[0]]) {
      nth_max_bin[0] = i;
    }

    for (n = 1; n < num_modes; n++) {
      if (histogram[i] >= histogram[nth_max_bin[n]] &&
           (!histogram[nth_max_bin[n-1]]
               || histogram[i] < histogram[nth_max_bin[n-1]])) {
        nth_max_bin[n] = i;
      }
    }
  }

  for (n = 0; n < num_modes; n++) {
    bin_counts += histogram[nth_max_bin[n]];
    ret += CBT_BIN_TO_MS(nth_max_bin[n])*histogram[nth_max_bin[n]];
    log_info(LD_CIRC, "Xm mode #%d: %u %u", n, CBT_BIN_TO_MS(nth_max_bin[n]),
             histogram[nth_max_bin[n]]);
  }

  /* The following assert is safe, because we don't get called when we
   * haven't observed at least CBT_MIN_MIN_CIRCUITS_TO_OBSERVE circuits. */
  tor_assert(bin_counts > 0);

  ret /= bin_counts;
  tor_free(histogram);
  tor_free(nth_max_bin);

  return ret;
}

/**
 * Output a histogram of current circuit build times to
 * the or_state_t state structure.
 */
void
circuit_build_times_update_state(const circuit_build_times_t *cbt,
                                 or_state_t *state)
{
  uint32_t *histogram;
  build_time_t i = 0;
  build_time_t nbins = 0;
  config_line_t **next, *line;

  histogram = circuit_build_times_create_histogram(cbt, &nbins);
  // write to state
  config_free_lines(state->BuildtimeHistogram);
  next = &state->BuildtimeHistogram;
  *next = NULL;

  state->TotalBuildTimes = cbt->total_build_times;
  state->CircuitBuildAbandonedCount = 0;

  for (i = 0; i < CBT_NCIRCUITS_TO_OBSERVE; i++) {
    if (cbt->circuit_build_times[i] == CBT_BUILD_ABANDONED)
      state->CircuitBuildAbandonedCount++;
  }

  for (i = 0; i < nbins; i++) {
    // compress the histogram by skipping the blanks
    if (histogram[i] == 0) continue;
    *next = line = tor_malloc_zero(sizeof(config_line_t));
    line->key = tor_strdup("CircuitBuildTimeBin");
    tor_asprintf(&line->value, "%d %d",
            CBT_BIN_TO_MS(i), histogram[i]);
    next = &(line->next);
  }

  if (!unit_tests) {
    if (!get_options()->AvoidDiskWrites)
      or_state_mark_dirty(get_or_state(), 0);
  }

  tor_free(histo