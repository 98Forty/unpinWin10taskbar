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
 * Retrieve and bounds-chec