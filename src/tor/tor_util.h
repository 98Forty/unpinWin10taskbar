/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file tor_util.h
 * \brief Headers for util.c
 **/

#ifndef TOR_UTIL_H
#define TOR_UTIL_H

#include "orconfig.h"
#include "torint.h"
#include "tor_compat.h"
#include "di_ops.h"
#include "testsupport.h"
#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
/* for the correct alias to struct stat */
#include <sys/stat.h>
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifndef O_TEXT
#define O_TEXT 0
#endif

/* Replace assert() with a variant that sends failures to the log before
 * calling assert() normally.
 */
#ifdef NDEBUG
/* Nobody should ever want to build with NDEBUG set.  99% of our asserts will
 * be outside the critical path anyway, so it's silly to disable bug-checking
 * throughout the entire program just because a few asserts are slowing you
 * down.  Profile, optimize the critical path, and keep debugging on.
 *
 * And I'm not just saying that because some of our asserts check
 * security-critical properties.
 */
#error "Sorry; we don't support building with NDEBUG."
#endif

/** Like assert(3), but send assertion failures to the log as well as to
 * stderr. */
#define tor_assert(expr) STMT_BEGIN                                     \
  if (PREDICT_UNLIKELY(!(expr))) {                                      \
    tor_assertion_failed_(SHORT_FILE__, __LINE__, __func__, #expr);     \
    abort();                                                            \
  } STMT_END

void tor_assertion_failed_(const char *fname, unsigned int line,
                           const char *func, const char *expr);

/* If we're building with dmalloc, we want all of our memory allocation
 * functions to take an extra file/line pair of arguments.  If not, not.
 * We define DMALLOC_PARAMS to the extra parameters to insert in the
 * function prototypes, and DMALLOC_ARGS to the extra arguments to add
 * to calls. */
#ifdef USE_DMALLOC
#define DMALLOC_PARAMS , const char *file, const int line
#define DMALLOC_ARGS , SHORT_FILE__, __LINE__
#else
#define DMALLOC_PARAMS
#define DMALLOC_ARGS
#endif

/** Define this if you want Tor to crash when any problem comes up,
 * so you can get a coredump and track things down. */
// #define tor_fragile_assert() tor_assert(0)
#define tor_fragile_assert()

/* Memory management */
void *tor_malloc_(size_t size DMALLOC_PARAMS) ATTR_MALLOC;
void *tor_malloc_zero_(size_t size DMALLOC_PARAMS) ATTR_MALLOC;
void *tor_calloc_(size_t nmemb, size_t size DMALLOC_PARAMS) ATTR_MALLOC;
void *tor_realloc_(void *ptr, size_t size DMALLOC_PARAMS);
char *tor_strdup_(const char *s DMALLOC_PARAMS) ATTR_MALLOC ATTR_NONNULL((1));
char *tor_strndup_(const char *s, size_t n DMALLOC_PARAMS)
  ATTR_MALLOC ATTR_NONNULL((1));
void *tor_memdup_(const void *mem, size_t len DMALLOC_PARAMS)
  ATTR_MALLOC ATTR_NONNULL((1));
void *tor_memdup_nulterm_(const void *mem, size_t len DMALLOC_PARAMS)
  ATTR_MALLOC ATTR_NONNULL((1));
void tor_free_(void *mem);
#ifdef USE_DMALLOC
extern int dmalloc_free(const char *file, const int line, void *pnt,
                        const int func_id);
#define tor_free(p) STMT_BEGIN \
    if (PREDICT_LIKELY((p)!=NULL)) {                \
      dmalloc_free(SHORT_FILE__, __LINE__, (p), 0); \
      (p)=NULL;                                     \
    }                                               \
  STMT_END
#else
/** Release memory allocated by tor_malloc, tor_realloc, tor_strdup, etc.
 * Unlike the free() function, tor_free() will still work on NULL pointers,
 * and it sets the pointer value to NULL after freeing it.
 *
 * This is a m