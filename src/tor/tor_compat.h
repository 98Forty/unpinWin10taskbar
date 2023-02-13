/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_COMPAT_H
#define TOR_COMPAT_H

#include "orconfig.h"
#include "torint.h"
#include "testsupport.h"
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#define WIN32_LEAN_AND_MEAN
#if defined(_MSC_VER) && (_MSC_VER < 1300)
#include <winsock.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#if defined(HAVE_PTHREAD_H) && !defined(_WIN32)
#include <pthread.h>
#endif
#include <stdarg.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET6_IN6_H
#include <netinet6/in6.h>
#endif

#include <stdio.h>
#include <errno.h>

#if defined (WINCE)
#include <fcntl.h>
#include <io.h>
#include <math.h>
#include <projects.h>
/* this is not exported as W .... */
#define SHGetPathFromIDListW SHGetPathFromIDList
/* wcecompat has vasprintf */
#define HAVE_VASPRINTF
/* no service here */
#ifdef NT_SERVICE
#undef NT_SERVICE
#endif
#endif // WINCE

#ifndef NULL_REP_IS_ZERO_BYTES
#error "It seems your platform does not represent NULL as zero. We can't cope."
#endif

#ifndef DOUBLE_0_REP_IS_ZERO_BYTES
#error "It seems your platform does not represent 0.0 as zeros. We can't cope."
#endif

#if 'a'!=97 || 'z'!=122 || 'A'!=65 || ' '!=32
#error "It seems that you encode characters in something other than ASCII."
#endif

/* ===== Compiler compatibility */

/* GCC can check printf and scanf types on arbitrary functions. */
#ifdef __GNUC__
#define CHECK_PRINTF(formatIdx, firstArg) \
   __attribute__ ((format(printf, formatIdx, firstArg)))
#else
#define CHECK_PRINTF(formatIdx, firstArg)
#endif
#ifdef __GNUC__
#define CHECK_SCANF(formatIdx, firstArg) \
   __attribute__ ((format(scanf, formatIdx, firstArg)))
#else
#define CHECK_SCANF(formatIdx, firstArg)
#endif

/* inline is __inline on windows. */
#ifdef _WIN32
#define INLINE __inline
#else
#define INLINE inline
#endif

/* Try to get a reasonable __func__ substitute in place. */
#if defined(_MSC_VER)
/* MSVC compilers before VC7 don't have __func__ at all; later ones call it
 * __FUNCTION__. */
#if _MSC_VER < 1300
#define __func__ "???"
#else
#define __func__ __FUNCTION__
#endif

#else
/* For platforms where autoconf works, make sure __func__ is defined
 * sanely. */
#ifndef HAVE_MACRO__func__
#ifdef HAVE_MACRO__FUNCTION__
#define __func__ __FUNCTION__
#elif HAVE_MACRO__FUNC__
#define __func__ __FUNC__
#else
#define __func__ "???"
#endif
#endif /* ifndef MAVE_MACRO__func__ */
#endif /* if not windows */

#if defined(_MSC_VER) && (_MSC_VER < 1300)
/* MSVC versions before 7 apparently don't believe that you can cast uint64_t
 * to double and really mean it. */
extern INLINE double U64_TO_DBL(uint64_t x) {
  int64_t i = (int64_t) x;
  return (i < 0) ? ((double) INT64_MAX) : (double) i;
}
#define DBL_TO_U64(x) ((uint64_t)(int64_t) (x))
#else
#define U64_TO_DBL(x) ((double) (x))
#define DBL_TO_U64(x) ((uint64_t) (x))
#endif

#ifdef ENUM_VALS_ARE_SIGNED
#define ENUM_BF(t) unsigned
#else
/** Wrapper for having a bitfield of an enumerated type. Where possible, we
 * just use the enumerated type (so the compiler can help us and notice
 * problems), but if enumerated types are unsigned, we must use unsigned,
 * so that the loss of precision doesn't make large values negative. */
#define ENUM_BF(t) t
#endif

/* GCC has several useful attributes. */
#if defined(__GNUC__) && __GNUC__ >= 3
#define ATTR_NORETURN __attribute__((noreturn))
#define ATTR_CONST __attribute__((const))
#define ATTR_MALLOC __attribute__((malloc))
#define ATTR_NORETURN __attribute__((noreturn))
/* Alas, nonnull is not at present a good idea for us.  We'd like to get
 * warnings when we pass NULL where we shouldn't (which nonnull does, albeit
 * spottily), but we don't want to tell the compiler to make optimizations
 * with the assumption that the argument can't be NULL (since this would make
 * many of our checks go away, and make our code less robust against
 * programming errors).  Unfortunately, nonnull currently does both of these
 * things, and there's no good way to split them up.
 *
 * #define ATTR_NONNULL(x) __attribute__((nonnull x)) */
#define ATTR_NONNULL(x)

/** Macro: Evaluates to <b>exp</b> and hints the compiler that the value
 * of <b>exp</b> will probably be true.
 *
 * In other words, "if (PREDICT_LIKELY(foo))" is the same as "if (foo)",
 * except that it tells the compiler that the branch will be taken most of the
 * time.  This can generate slightly better code with some CPUs.
 */
#define PREDICT_LIKELY(exp) __builtin_expect(!!(exp), 1)
/** Macro: Evaluates to <b>exp</b> and hints the compiler that the value
 * of <b>exp</b> will probably be false.
 *
 * In other words, "if (PREDICT_UNLIKELY(foo))" is the same as "if (foo)",
 * except that it tells the compiler that the branch will usually not be
 * taken.  This can generate slightly better code with some CPUs.
 */
#define PREDICT_UNLIKELY(exp) __builtin_expect(!!(exp), 0)
#else
#define ATTR_NORETURN
#define ATTR_CONST
#define ATTR_MALLOC
#define ATTR_NORETURN
#define ATTR_NONNULL(x)
#define PREDICT_LIKELY(exp) (exp)
#define PREDICT_UNLIKELY(exp) (exp)
#endif

/** Expands to a syntactically valid empty statement.  */
#define STMT_NIL (void)0

/** Expands to a syntactically valid empty statement, explicitly (void)ing its
 * argument. */
#define STMT_VOID(a) while (0) { (void)(a); }

#ifdef __GNUC__
/** STMT_BEGIN and STMT_END are used to wrap blocks inside macros so that
 * the macro can be used as if it were a single C statement. */
#define STMT_BEGIN (void) ({
#define STMT_END })
#elif defined(sun) || defined(__sun__)
#define STMT_BEGIN if (1) {
#define STMT_END } else STMT_NIL
#else
#define STMT_BEGIN do {
#define STMT_END } while (0)
#endif

/* ===== String compatibility */
#ifdef _WIN32
/* Windows names string functions differently from most other platforms. */
#define strncasecmp _strnicmp
#define strcasecmp _stricmp
#endif
#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz) ATTR_NONNULL((1,2));
#endif
#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t siz) ATTR_NONNULL((1,2));
#endif

#ifdef _MSC_VER
/** Casts the uint64_t value in <b>a</b> to the right type for an argument
 * to printf. */
#define U64_PRINTF_ARG(a) (a)
/** Casts the uint64_t* value in <b>a</b> to the right type for an argument
 * to scanf. */
#define U64_SCANF_ARG(a) (a)
/** Expands to a literal uint64_t-typed constant for the value <b>n</b>. */
#define U64_LITERAL(n) (n ## ui64)
#define I64_PRINTF_ARG(a) (a)
#define I64_SCANF_ARG(a) (a)
#define I64_LITERAL(n) (n ## i64)
#else
#define U64_PRINTF_ARG(a) ((long long unsigned int)(a))
#define U64_SCANF_ARG(a) ((long long unsigned int*)(a))
#define U64_LITERAL(n) (n ## llu)
#define I64_PRINTF_ARG(a) ((long long signed int)(a))
#define I64_SCANF_ARG(a) ((long long signed int*)(a))
#define I64_LITERAL(n) (n ## ll)
#endif

#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
/** The formatting string used to put a uint64_t value in a printf() or
 * scanf() function.  See also U64_PRINTF_ARG and U64_SCANF_ARG. */
#define U64_FORMAT "%I64u"
#define I64_FORMAT "%I64d"
#else
#define U64_FORMAT "%llu"
#define I64_FORMAT "%lld"
#endif

#if (SIZEOF_INTPTR_T == SIZEOF_INT)
#define INTPTR_T_FORMAT "%d"
#define INTPTR_PRINTF_ARG(x) ((int)(x))
#elif (SIZEOF_INTPTR_T == SIZEOF_LONG)
#define INTPTR_T_FORMAT "%ld"
#define INTPTR_PRINTF_ARG(x) ((long)(x))
#elif (SIZEOF_INTPTR_T == 8)
#define INTPTR_T_FORMAT I64_FORMAT
#define INTPTR_PRINTF_ARG(x) I64_PRINTF_ARG(x)
#else
#error Unknown: SIZEOF_INTPTR_T
#endif

/** Represents an mmaped file. Allocated via tor_mmap_file; freed with
 * tor_munmap_file. */
typedef struct tor_mmap_t {
  const char *data; /**< Mapping of the file's contents. */
  size_t size; /**< Size of the file. */

  /* None of the fields below should be accessed from outside compat.c */
#ifdef HAVE_SYS_MMAN_H
  size_t mapping_size; /**< Size of the actual mapping. (This is this file
                        * size, rounded up to the nearest page.) */
#elif defined _WIN32
  HANDLE mmap_handle;
#endif

} tor_mmap_t;

tor_mmap_t *tor_mmap_file(const char *filename) ATTR_NONNULL((1));
void tor_munmap_file(tor_mmap_t *handle) ATTR_NONNULL((1));

int tor_snprintf(char *str, size_t size, const char *format, ...)
  CHECK_PRINTF(3,4) ATTR_NONNULL((1,3));
int tor_vsnprintf(char *str, size_t size, const char *format, va_list args)
  CHECK_PRINTF(3,0) ATTR_NONNULL((1,3));

int tor_asprintf(char **strp, const char *fmt, ...)
  CHECK_PRINTF(2,3);
int tor_vasprintf(char **strp, const char *fmt, va_list args)
  CHECK_PRINTF(2,0);

const void *tor_memmem(const void *haystack, size_t hlen, const void *needle,
                       size_t nlen) ATTR_NONNULL((1,3));
static const void *tor_memstr(const void *haystack, size_t hlen,
                           const char *needle) ATTR_NONNULL((1,3));
static INLINE const void *
tor_memstr(const void *haystack, size_t hlen, const char *needle)
{
  return tor_memmem(haystack, hlen, needle, strlen(needle));
}

/* Much of the time when we're checking ctypes, we're doing spec compliance,
 * which all assumes we're doing ASCII. */
#define DECLARE_CTYPE_FN(name)                                          \
  static int TOR_##name(char c);                                        \
  extern const uint32_t TOR_##name##_TABLE[];                           \
  static INLINE int TOR_##name(char c) {                                \
    uint8_t u = c;                                                      \
    return !!(TOR_##name##_TABLE[(u >> 5) & 7] & (1 << (u & 31)));      \
  }
DECLARE_CTYPE_FN(ISALPHA)
DECLARE_CTYPE_FN(ISALNUM)
DECLARE_CTYPE_FN(ISSPACE)
DECLARE_CTYPE_FN(ISDIGIT)
DECLARE_CTYPE_FN(ISXDIGIT)
DECLARE_CTYPE_FN(ISPRINT)
DECLARE_CTYPE_FN(ISLOWER)
DECLARE_CTYPE_FN(ISUPPER)
extern const char TOR_TOUPPER_TABLE[];
extern const char TOR_TOLOWER_TABLE[];
#define TOR_TOLOWER(c) (TOR_TOLOWER_TABLE[(uint8_t)c])
#define TOR_TOUPPER(c) (TOR_TOUPPER_TABLE[(uint8_t)c])

char *tor_strtok_r_impl(char *str, const char *sep, char **lasts);
#ifdef HAVE_STRTOK_R
#define tor_strtok_r(str, sep, lasts) strtok_r(str, sep, lasts)
#else
#define tor_strtok_r(str, sep, lasts) tor_strtok_r_impl(str, sep, lasts)
#endif

#ifdef _WIN32
#define SHORT_FILE__ (tor_fix_source_file(__FILE__))
const char *tor_fix_source_file(const char *fname);
#else
#define SHORT_FILE__ (__FILE__)
#define tor_fix_source_file(s) (s)
#endif

/* ===== Time compatibility */
#if !defined(HAVE_GETTIMEOFDAY) && !defined(HAVE_STRUCT_TIMEVAL_TV_SEC)
/** Implementation of timeval for platforms that don't have it. */
struct timeval {
  time_t tv_sec;
  unsigned int tv_usec;
};
#endif

void tor_gettimeofday(struct timeval *timeval);

struct tm *tor_localtime_r(const time_t *timep, struct tm *result);
struct tm *tor_gmtime_r(const time_t *timep, struct tm *result);

#ifndef timeradd
/** Replacement for timeradd on platforms that do not have it: sets tvout to
 * the sum of tv1 and tv2. */
#define timeradd(tv1,tv2,tvout) \
  do {                                                  \
    (tvout)->tv_sec = (tv1)->tv_sec + (tv2)->tv_sec;    \
    (tvout)->tv_usec = (tv1)->tv_usec + (tv2)->tv_usec; \
    if ((tvout)->tv_usec >= 1000000) {                  \
      (tvout)->tv_usec -= 1000000;                      \
      (tvout)->tv_sec++;                                \
    }                                                   \
  } while (0)
#endif

#ifndef timersub
/** Replacement for timersub on platforms that do not have it: sets tvout to
 * tv1 minus tv2. */
#define timersub(tv1,tv2,tvout) \
  do {                                                  \
    (tvout)->tv_sec = (tv1)->tv_sec - (tv2)->tv_sec;    \
    (tvout)->tv_usec = (tv1)->tv_usec - (tv2)->tv_usec; \
    if ((tvout)->tv_usec < 0) {                         \
      (tvout)->tv_usec += 1000000;                      \
      (tvout)->tv_sec--;                                \
    }                                                   \
  } while (0)
#endif

#ifndef timercmp
/** Replacement for timersub on platforms that do not have it: returns true
 * iff the relational operator "op" makes the expression tv1 op tv2 true.
 *
 * Note that while this definition should work for all boolean opeators, some
 * platforms' native timercmp definitions do not support >=, <=, or ==.  So
 * don't use those.
 */
#define timercmp(tv1,tv2,op)                    \
  (((tv1)->tv_sec == (tv2)->tv_sec) ?           \
   ((tv1)->tv_usec op (tv2)->tv_usec) :         \
   ((tv1)->tv_sec op (tv2)->tv_sec))
#endif

/* ===== File compatibility */
int tor_open_cloexec(const char *path, int flags, unsigned mode);
FILE *tor_fopen_cloexec(const char *path, const char *mode);

int replace_file(const char *from, const char *to);
int touch_file(const char *fname);

typedef struct tor_lockfile_t tor_lockfile_t;
tor_lockfile_t *tor_lockfile_lock(const char *filename, int blocking,
                                  int *locked_out);
void tor_lockfile_unlock(tor_lockfile_t *lockfile);

off_t tor_fd_getpos(int fd);
int tor_fd_setpos(int fd, off_t pos);
int tor_fd_seekend(int fd);

#ifdef _WIN32
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

/* ===== Net compatibility */

#if (SIZEOF_SOCKLEN_T == 0)
typedef int socklen_t;
#endif

#ifdef _WIN32
/* XXX Actually, this should arguably be SOCKET; we use intptr_t here so that
 * any inadvertant checks for the socket being <= 0 or > 0 will probably
 * still work. */
#define tor_socket_t intptr_t
#define TOR_SOCKET_T_FORMAT INTPTR_T_FORMAT
#define SOCKET_OK(s) ((SOCKET)(s) != INVALID_SOCKET)
#define TOR_INVALID_SOCKET INVALID_SOCKET
#else
/** Type used for a network socket. */
#define tor_socket_t int
#define TOR_SOCKET_T_FORMAT "%d"
/** Macro: true iff 's' is a possible value for a valid initialized socket. */
#define SOCKET_OK(s) ((s) >= 0)
/** Error/uninitialized value for a tor_socket_t. */
#define TOR_INVALID_SOCKET (-1)
#endif

int tor_close_socket_simple(tor_socket_t s);
int tor_close_socket(tor_socket_t s);
tor_socket_t tor_open_socket_with_extensions(
                        