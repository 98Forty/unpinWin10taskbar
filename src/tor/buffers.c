/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file buffers.c
 * \brief Implements a generic interface buffer.  Buffers are
 * fairly opaque string holders that can read to or flush from:
 * memory, file descriptors, or TLS connections.
 **/
#define BUFFERS_PRIVATE
#include "or.h"
#include "addressmap.h"
#include "buffers.h"
#include "config.h"
#include "connection_edge.h"
#include "connection_or.h"
#include "control.h"
#include "reasons.h"
#include "ext_orport.h"
#include "tor_util.h"
#include "torlog.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

//#define PARANOIA

#ifdef PARANOIA
/** Helper: If PARANOIA is defined, assert that the buffer in local variable
 * <b>buf</b> is well-formed. */
#define check() STMT_BEGIN assert_buf_ok(buf); STMT_END
#else
#define check() STMT_NIL
#endif

/* Implementation notes:
 *
 * After flirting with memmove, and dallying with ring-buffers, we're finally
 * getting up to speed with the 1970s and implementing buffers as a linked
 * list of small chunks.  Each buffer has such a list; data is removed from
 * the head of the list, and added at the tail.  The list is singly linked,
 * and the buffer keeps a pointer to the head and the tail.
 *
 * Every chunk, except the tail, contains at least one byte of data.  Data in
 * each chunk is contiguous.
 *
 * When you need to treat the first N characters on a buffer as a contiguous
 * string, use the buf_pullup function to make them so.  Don't do this more
 * than necessary.
 *
 * The major free Unix kernels have handled buffers like this since, like,
 * forever.
 */

static int parse_socks(const char *data, size_t datalen, socks_request_t *req,
                       int log_sockstype, int safe_socks, ssize_t *drain_out,
                       size_t *want_length_out);
static int parse_socks_client(const uint8_t *data, size_t datalen,
                              int state, char **reason,
                              ssize_t *drain_out);

/* Chunk manipulation functions */

/** A single chunk on a buffer or in a freelist. */
typedef struct chunk_t {
  struct chunk_t *next; /**< The next chunk on the buffer or freelist. */
  size_t datalen; /**< The number of bytes stored in this chunk */
  size_t memlen; /**< The number of usable bytes of storage in <b>mem</b>. */
  char *data; /**< A pointer to the first byte of data stored in <b>mem</b>. */
  char mem[FLEXIBLE_ARRAY_MEMBER]; /**< The actual memory used for storage in
                * this chunk. */
} chunk_t;

#define CHUNK_HEADER_LEN STRUCT_OFFSET(chunk_t, mem[0])

/** Return the number of bytes needed to allocate a chunk to hold
 * <b>memlen</b> bytes. */
#define CHUNK_ALLOC_SIZE(memlen) (CHUNK_HEADER_LEN + (memlen))
/** Return the number of usable bytes in a chunk allocated with
 * malloc(<b>memlen</b>). */
#define CHUNK_SIZE_WITH_ALLOC(memlen) ((memlen) - CHUNK_HEADER_LEN)

/** Return the next character in <b>chunk</b> onto which data can be appended.
 * If the chunk is full, this might be off the end of chunk->mem. */
static INLINE char *
CHUNK_WRITE_PTR(chunk_t *chunk)
{
  return chunk->data + chunk->datalen;
}

/** Return the number of bytes that can be written onto <b>chunk</b> without
 * running out of space. */
static INLINE size_t
CHUNK_REMAINING_CAPACITY(const chunk_t *chunk)
{
  return (chunk->mem + chunk->memlen) - (chunk->data + chunk->datalen);
}

/** Move all bytes stored in <b>chunk</b> to the front of <b>chunk</b>->mem,
 * to free up space at the end. */
static INLINE void
chunk_repack(chunk_t *chunk)
{
  if (chunk->datalen && chunk->data != &chunk->mem[0]) {
    memmove(chunk->mem, chunk->data, chunk->datalen);
  }
  chunk->data = &chunk->mem[0];
}

#if defined(ENABLE_BUF_FREELISTS) || defined(RUNNING_DOXYGEN)
/** A freelist of chunks. */
typedef struct chunk_freelist_t {
  size_t alloc_size; /**< What size chunks does this freelist hold? */
  int max_length; /**< Never allow more than this number of chunks in the
                   * freelist. */
  int slack; /**< When trimming the freelist, leave this number of extra
              * chunks beyond lowest_length.*/
  int cur_length; /**< How many chunks on the freelist now? */
  int lowest_length; /**< What's the smallest value of cur_length since the
                      * last time we cleaned this freelist? */
  uint64_t n_alloc;
  uint64_t n_free;
  uint64_t n_hit;
  chunk_t *head; /**< First chunk on the freelist. */
} chunk_freelist_t;

/** Macro to help define freelists. */
#define FL(a,m,s) { a, m, s, 0, 0, 0, 0, 0, NULL }

/** Static array of freelists, sorted by alloc_len, terminated by an entry
 * with alloc_size of 0. */
static chunk_freelist_t freelists[] = {
  FL(4096, 256, 8), FL(8192, 128, 4), FL(16384, 64, 4), FL(32768, 32, 2),
  FL(0, 0, 0)
};
#undef FL
/** How many times have we looked for a chunk of a size that no freelist
 * could help with? */
static uint64_t n_freelist_miss = 0;

static void assert_freelist_ok(chunk_freelist_t *fl);

/** Return the freelist to hold chunks of size <b>alloc</b>, or NULL if
 * no freelist exists for that size. */
static INLINE chunk_freelist_t *
get_freelist(size_t alloc)
{
  int i;
  for (i=0; (freelists[i].alloc_size <= alloc &&
             freelists[i].alloc_size); ++i ) {
    if (freelists[i].alloc_size == alloc) {
      return &freelists[i];
    }
  }
  return NULL;
}

/** Deallocate a chunk or put it on a freelist */
static void
chunk_free_unchecked(chunk_t *chunk)
{
  size_t alloc;
  chunk_freelist_t *freelist;

  alloc = CHUNK_ALLOC_SIZE(chunk->memlen);
  freelist = get_freelist(alloc);
  if (freelist && freelist->cur_length < freelist->max_length) {
    chunk->next = freelist->head;
    freelist->head = chunk;
    ++freelist->cur_length;
  } else {
    if (freelist)
      ++freelist->n_free;
    tor_free(chunk);
  }
}

/** Allocate a new chunk with a given allocation size, or get one from the
 * freelist.  Note that a chunk with allocation size A can actually hold only
 * CHUNK_SIZE_WITH_ALLOC(A) bytes in its mem field. */
static INLINE chunk_t *
chunk_new_with_alloc_size(size_t alloc)
{
  chunk_t *ch;
  chunk_freelist_t *freelist;
  tor_assert(alloc >= sizeof(chunk_t));
  freelist = get_freelist(alloc);
  if (freelist && freelist->head) {
    ch = freelist->head;
    freelist->head = ch->next;
    if (--freelist->cur_length < freelist->lowest_length)
      freelist->lowest_length = freelist->cur_length;
    ++freelist->n_hit;
  } else {
    if (freelist)
      ++freelist->n_alloc;
    else
      ++n_freelist_miss;
    ch = tor_malloc(alloc);
  }
  ch->next = NULL;
  ch->datalen = 0;
  ch->memlen = CHUNK_SIZE_WITH_ALLOC(alloc);
  ch->data = &ch->mem[0];
  return ch;
}
#else
static void
chunk_free_unchecked(chunk_t *chunk)
{
  tor_free(chunk);
}
static INLINE chunk_t *
chunk_new_with_alloc_size(size_t alloc)
{
  chunk_t *ch;
  ch = tor_malloc(alloc);
  ch->next = NULL;
  ch->datalen = 0;
  ch->memlen = CHUNK_SIZE_WITH_ALLOC(alloc);
  ch->data = &ch->mem[0];
  return ch;
}
#endif

/** Expand <b>chunk</b> until it can hold <b>sz</b> bytes, and return a
 * new pointer to <b>chunk</b>.  Old pointers are no longer valid. */
static INLINE chunk_t *
chunk_grow(chunk_t *chunk, size_t sz)
{
  off_t offset;
  tor_assert(sz > chunk->memlen);
  offset = chunk->data - chunk->mem;
  chunk = tor_realloc(chunk, CHUNK_ALLOC_SIZE(sz));
  chunk->memlen = sz;
  chunk-