/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file container.c
 * \brief Implements a smartlist (a resizable array) along
 * with helper functions to use smartlists.  Also includes
 * hash table implementations of a string-to-void* map, and of
 * a digest-to-void* map.
 **/

#include "tor_compat.h"
#include "tor_util.h"
#include "torlog.h"
#include "container.h"
#include "crypto.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ht.h"

/** All newly allocated smartlists have this capacity. */
#define SMARTLIST_DEFAULT_CAPACITY 16

/** Allocate and return an empty smartlist.
 */
smartlist_t *
smartlist_new(void)
{
  smartlist_t *sl = tor_malloc(sizeof(smartlist_t));
  sl->num_used = 0;
  sl->capacity = SMARTLIST_DEFAULT_CAPACITY;
  sl->list = tor_malloc(sizeof(void *) * sl->capacity);
  return sl;
}

/** Deallocate a smartlist.  Does not release storage associated with the
 * list's elements.
 */
void
smartlist_free(smartlist_t *sl)
{
  if (!sl)
    return;
  tor_free(sl->list);
  tor_free(sl);
}

/** Remove all elements from the list.
 */
void
smartlist_clear(smartlist_t *sl)
{
  sl->num_used = 0;
}

/** Make sure that <b>sl</b> can hold at least <b>size</b> entries. */
static INLINE void
smartlist_ensure_capacity(smartlist_t *sl, int size)
{
#if SIZEOF_SIZE_T > SIZEOF_INT
#define MAX_CAPACITY (INT_MAX)
#else
#define MAX_CAPACITY (int)((SIZE_MAX / (sizeof(void*))))
#endif
  if (size > sl->capacity) {
    int higher = sl->capacity;
    if (PREDICT_UNLIKELY(size > MAX_CAPACITY/2)) {
      tor_assert(size <= MAX_CAPACITY);
      higher = MAX_CAPACITY;
    } else {
      while (size > higher)
        higher *= 2;
    }
    sl->capacity = higher;
    sl->list = tor_realloc(sl->list, sizeof(void*)*((size_t)sl->capacity));
  }
}

/** Append element to the end of the list. */
void
smartlist_add(smartlist_t *sl, void *element)
{
  smartlist_ensure_capacity(sl, sl->num_used+1);
  sl->list[sl->num_used++] = element;
}

/** Append each element from S2 to the end of S1. */
void
smartlist_add_all(smartlist_t *s1, const smartlist_t *s2)
{
  int new_size = s1->num_used + s2->num_used;
  tor_assert(new_size >= s1->num_used); /* check for overflow. */
  smartlist_ensure_capacity(s1, new_size);
  memcpy(s1->list + s1->num_used, s2->list, s2->num_used*sizeof(void*));
  s1->num_used = new_size;
}

/** Remove all elements E from sl such that E==element.  Preserve
 * the order of any elements before E, but elements after E can be
 * rearranged.
 */
void
smartlist_remove(smartlist_t *sl, const void *element)
{
  int i;
  if (element == NULL)
    return;
  for (i=0; i < sl->num_used; i++)
    if (sl->list[i] == element) {
      sl->list[i] = sl->list[--sl->num_used]; /* swap with the end */
      i--; /* so we process the new i'th element */
    }
}

/** If <b>sl</b> is nonempty, remove and return the final element.  Otherwise,
 * return NULL. */
void *
smartlist_pop_last(smartlist_t *sl)
{
  tor_assert(sl);
  if (sl->num_used)
    return sl->list[--sl->num_used];
  else
    return NULL;
}

/** Reverse the order of the items in <b>sl</b>. */
void
smartlist_reverse(smartlist_t *sl)
{
  int i, j;
  void *tmp;
  tor_assert(sl);
  for (i = 0, j = sl->num_used-1; i < j; ++i, --j) {
    tmp = sl->list[i];
    sl->list[i] = sl->list[j];
    sl->list[j] = tmp;
  }
}

/** If there are any strings in sl equal to element, remove and free them.
 * Does not preserve order. */
void
smartlist_string_r