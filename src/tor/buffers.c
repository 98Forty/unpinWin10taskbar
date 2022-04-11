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
  chunk->data = chunk->mem + offset;
  return chunk;
}

/** If a read onto the end of a chunk would be smaller than this number, then
 * just start a new chunk. */
#define MIN_READ_LEN 8
/** Every chunk should take up at least this many bytes. */
#define MIN_CHUNK_ALLOC 256
/** No chunk should take up more than this many bytes. */
#define MAX_CHUNK_ALLOC 65536

/** Return the allocation size we'd like to use to hold <b>target</b>
 * bytes. */
static INLINE size_t
preferred_chunk_size(size_t target)
{
  size_t sz = MIN_CHUNK_ALLOC;
  while (CHUNK_SIZE_WITH_ALLOC(sz) < target) {
    sz <<= 1;
  }
  return sz;
}

/** Remove from the freelists most chunks that have not been used since the
 * last call to buf_shrink_freelists(). */
void
buf_shrink_freelists(int free_all)
{
#ifdef ENABLE_BUF_FREELISTS
  int i;
  disable_control_logging();
  for (i = 0; freelists[i].alloc_size; ++i) {
    int slack = freelists[i].slack;
    assert_freelist_ok(&freelists[i]);
    if (free_all || freelists[i].lowest_length > slack) {
      int n_to_free = free_all ? freelists[i].cur_length :
        (freelists[i].lowest_length - slack);
      int n_to_skip = freelists[i].cur_length - n_to_free;
      int orig_length = freelists[i].cur_length;
      int orig_n_to_free = n_to_free, n_freed=0;
      int orig_n_to_skip = n_to_skip;
      int new_length = n_to_skip;
      chunk_t **chp = &freelists[i].head;
      chunk_t *chunk;
      while (n_to_skip) {
        if (! (*chp)->next) {
          log_warn(LD_BUG, "I wanted to skip %d chunks in the freelist for "
                   "%d-byte chunks, but only found %d. (Length %d)",
                   orig_n_to_skip, (int)freelists[i].alloc_size,
                   orig_n_to_skip-n_to_skip, freelists[i].cur_length);
          assert_freelist_ok(&freelists[i]);
          goto done;
        }
        // tor_assert((*chp)->next);
        chp = &(*chp)->next;
        --n_to_skip;
      }
      chunk = *chp;
      *chp = NULL;
      while (chunk) {
        chunk_t *next = chunk->next;
        tor_free(chunk);
        chunk = next;
        --n_to_free;
        ++n_freed;
        ++freelists[i].n_free;
      }
      if (n_to_free) {
        log_warn(LD_BUG, "Freelist length for %d-byte chunks may have been "
                 "messed up somehow.", (int)freelists[i].alloc_size);
        log_warn(LD_BUG, "There were %d chunks at the start.  I decided to "
                 "keep %d. I wanted to free %d.  I freed %d.  I somehow think "
                 "I have %d left to free.",
                 freelists[i].cur_length, n_to_skip, orig_n_to_free,
                 n_freed, n_to_free);
      }
      // tor_assert(!n_to_free);
      freelists[i].cur_length = new_length;
      log_info(LD_MM, "Cleaned freelist for %d-byte chunks: original "
               "length %d, kept %d, dropped %d.",
               (int)freelists[i].alloc_size, orig_length,
               orig_n_to_skip, orig_n_to_free);
    }
    freelists[i].lowest_length = freelists[i].cur_length;
    assert_freelist_ok(&freelists[i]);
  }
 done:
  enable_control_logging();
#else
  (void) free_all;
#endif
}

/** Describe the current status of the freelists at log level <b>severity</b>.
 */
void
buf_dump_freelist_sizes(int severity)
{
#ifdef ENABLE_BUF_FREELISTS
  int i;
  tor_log(severity, LD_MM, "====== Buffer freelists:");
  for (i = 0; freelists[i].alloc_size; ++i) {
    uint64_t total = ((uint64_t)freelists[i].cur_length) *
      freelists[i].alloc_size;
    tor_log(severity, LD_MM,
        U64_FORMAT" bytes in %d %d-byte chunks ["U64_FORMAT
        " misses; "U64_FORMAT" frees; "U64_FORMAT" hits]",
        U64_PRINTF_ARG(total),
        freelists[i].cur_length, (int)freelists[i].alloc_size,
        U64_PRINTF_ARG(freelists[i].n_alloc),
        U64_PRINTF_ARG(freelists[i].n_free),
        U64_PRINTF_ARG(freelists[i].n_hit));
  }
  tor_log(severity, LD_MM, U64_FORMAT" allocations in non-freelist sizes",
      U64_PRINTF_ARG(n_freelist_miss));
#else
  (void)severity;
#endif
}

/** Magic value for buf_t.magic, to catch pointer errors. */
#define BUFFER_MAGIC 0xB0FFF312u
/** A resizeable buffer, optimized for reading and writing. */
struct buf_t {
  uint32_t magic; /**< Magic cookie for debugging: Must be set to
                   *   BUFFER_MAGIC. */
  size_t datalen; /**< How many bytes is this buffer holding right now? */
  size_t default_chunk_size; /**< Don't allocate any chunks smaller than
                              * this for this buffer. */
  chunk_t *head; /**< First chunk in the list, or NULL for none. */
  chunk_t *tail; /**< Last chunk in the list, or NULL for none. */
};

/** Collapse data from the first N chunks from <b>buf</b> into buf->head,
 * growing it as necessary, until buf->head has the first <b>bytes</b> bytes
 * of data from the buffer, or until buf->head has all the data in <b>buf</b>.
 *
 * If <b>nulterminate</b> is true, ensure that there is a 0 byte in
 * buf->head->mem right after all the data. */
static void
buf_pullup(buf_t *buf, size_t bytes, int nulterminate)
{
  chunk_t *dest, *src;
  size_t capacity;
  if (!buf->head)
    return;

  check();
  if (buf->datalen < bytes)
    bytes = buf->datalen;

  if (nulterminate) {
    capacity = bytes + 1;
    if (buf->head->datalen >= bytes && CHUNK_REMAINING_CAPACITY(buf->head)) {
      *CHUNK_WRITE_PTR(buf->head) = '\0';
      return;
    }
  } else {
    capacity = bytes;
    if (buf->head->datalen >= bytes)
      return;
  }

  if (buf->head->memlen >= capacity) {
    /* We don't need to grow the first chunk, but we might need to repack it.*/
    size_t needed = capacity - buf->head->datalen;
    if (CHUNK_REMAINING_CAPACITY(buf->head) < needed)
      chunk_repack(buf->head);
    tor_assert(CHUNK_REMAINING_CAPACITY(buf->head) >= needed);
  } else {
    chunk_t *newhead;
    size_t newsize;
    /* We need to grow the chunk. */
    chunk_repack(buf->head);
    newsize = CHUNK_SIZE_WITH_ALLOC(preferred_chunk_size(capacity));
    newhead = chunk_grow(buf->head, newsize);
    tor_assert(newhead->memlen >= capacity);
    if (newhead != buf->head) {
      if (buf->tail == buf->head)
        buf->tail = newhead;
      buf->head = newhead;
    }
  }

  dest = buf->head;
  while (dest->datalen < bytes) {
    size_t n = bytes - dest->datalen;
    src = dest->next;
    tor_assert(src);
    if (n > src->datalen) {
      memcpy(CHUNK_WRITE_PTR(dest), src->data, src->datalen);
      dest->datalen += src->datalen;
      dest->next = src->next;
      if (buf->tail == src)
        buf->tail = dest;
      chunk_free_unchecked(src);
    } else {
      memcpy(CHUNK_WRITE_PTR(dest), src->data, n);
      dest->datalen += n;
      src->data += n;
      src->datalen -= n;
      tor_assert(dest->datalen == bytes);
    }
  }

  if (nulterminate) {
    tor_assert(CHUNK_REMAINING_CAPACITY(buf->head));
    *CHUNK_WRITE_PTR(buf->head) = '\0';
  }

  check();
}

/** Resize buf so it won't hold extra memory that we haven't been
 * using lately.
 */
void
buf_shrink(buf_t *buf)
{
  (void)buf;
}

/** Remove the first <b>n</b> bytes from buf. */
static INLINE void
buf_remove_from_front(buf_t *buf, size_t n)
{
  tor_assert(buf->datalen >= n);
  while (n) {
    tor_assert(buf->head);
    if (buf->head->datalen > n) {
      buf->head->datalen -= n;
      buf->head->data += n;
      buf->datalen -= n;
      return;
    } else {
      chunk_t *victim = buf->head;
      n -= victim->datalen;
      buf->datalen -= victim->datalen;
      buf->head = victim->next;
      if (buf->tail == victim)
        buf->tail = NULL;
      chunk_free_unchecked(victim);
    }
  }
  check();
}

/** Create and return a new buf with default chunk capacity <b>size</b>.
 */
buf_t *
buf_new_with_capacity(size_t size)
{
  buf_t *b = buf_new();
  b->default_chunk_size = preferred_chunk_size(size);
  return b;
}

/** Allocate and return a new buffer with default capacity. */
buf_t *
buf_new(void)
{
  buf_t *buf = tor_malloc_zero(sizeof(buf_t));
  buf->magic = BUFFER_MAGIC;
  buf->default_chunk_size = 4096;
  return buf;
}

/** Remove all data from <b>buf</b>. */
void
buf_clear(buf_t *buf)
{
  chunk_t *chunk, *next;
  buf->datalen = 0;
  for (chunk = buf->head; chunk; chunk = next) {
    next = chunk->next;
    chunk_free_unchecked(chunk);
  }
  buf->head = buf->tail = NULL;
}

/** Return the number of bytes stored in <b>buf</b> */
size_t
buf_datalen(const buf_t *buf)
{
  return buf->datalen;
}

/** Return the total length of all chunks used in <b>buf</b>. */
size_t
buf_allocation(const buf_t *buf)
{
  size_t total = 0;
  const chunk_t *chunk;
  for (chunk = buf->head; chunk; chunk = chunk->next) {
    total += chunk->memlen;
  }
  return total;
}

/** Return the number of bytes that can be added to <b>buf</b> without
 * performing any additional allocation. */
size_t
buf_slack(const buf_t *buf)
{
  if (!buf->tail)
    return 0;
  else
    return CHUNK_REMAINING_CAPACITY(buf->tail);
}

/** Release storage held by <b>buf</b>. */
void
buf_free(buf_t *buf)
{
  if (!buf)
    return;

  buf_clear(buf);
  buf->magic = 0xdeadbeef;
  tor_free(buf);
}

/** Return a new copy of <b>in_chunk</b> */
static chunk_t *
chunk_copy(const chunk_t *in_chunk)
{
  chunk_t *newch = tor_memdup(in_chunk, CHUNK_ALLOC_SIZE(in_chunk->memlen));
  newch->next = NULL;
  if (in_chunk->data) {
    off_t offset = in_chunk->data - in_chunk->mem;
    newch->data = newch->mem + offset;
  }
  return newch;
}

/** Return a new copy of <b>buf</b> */
buf_t *
buf_copy(const buf_t *buf)
{
  chunk_t *ch;
  buf_t *out = buf_new();
  out->default_chunk_size = buf->default_chunk_size;
  for (ch = buf->head; ch; ch = ch->next) {
    chunk_t *newch = chunk_copy(ch);
    if (out->tail) {
      out->tail->next = newch;
      out->tail = newch;
    } els