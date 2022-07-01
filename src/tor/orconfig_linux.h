/* orconfig.h.  Generated from orconfig.h.in by configure.  */
/* orconfig.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* tor's configuration directory */
#define CONFDIR "/usr/local/etc/tor"

/* Defined if we have a curve25519 implementation */
#define CURVE25519_ENABLED 1

/* Enable dmalloc's malloc function check */
/* #undef DMALLOC_FUNC_CHECK */

/* Define to 1 iff memset(0) sets doubles to 0.0 */
#define DOUBLE_0_REP_IS_ZERO_BYTES 1

/* Defined if we try to use freelists for buffer RAM chunks */
#define ENABLE_BUF_FREELISTS 1

/* Defined if we default to host local appdata paths on Windows */
/* #undef ENABLE_LOCAL_APPDATA */

/* Defined if we will try to use multithreading */
#define ENABLE_THREADS 1

/* Define if enum is always signed */
/* #undef ENUM_VALS_ARE_SIGNED */

/* Define to nothing if C supports flexible array members, and to 1 if it does
   not. That way, with a declaration like `struct s { int n; double
   d[FLEXIBLE_ARRAY_MEMBER]; };', the struct hack can be used with pre-C99
   compilers. When computing the size of such an object, don't use 'sizeof
   (struct s)' as it overestimates the size. Use 'offsetof (struct s, d)'
   instead. Don't use 'offsetof (struct s, d[0])', as this doesn't work with
   MSVC and with C++ compilers. */
#define FLEXIBLE_ARRAY_MEMBER /**/

/* Define to 1 if you have the `accept4' function. */
#define HAVE_ACCEPT4 1

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the <assert.h> header file. */
#define HAVE_ASSERT_H 1

/* Define to 1 if you have the `backtrace' function. */
#define HAVE_BACKTRACE 1

/* Define to 1 if you have the `backtrace_symbols_fd' function. */
#define HAVE_BACKTRACE_SYMBOLS_FD 1

/* Defined if the requested minimum BOOST version is satisfied */
#define HAVE_BOOST 1

/* Define to 1 if you have <boost/filesystem/path.hpp> */
#define HAVE_BOOST_FILESYSTEM_PATH_HPP 1

/* Define to 1 if you have <boost/system/error_code.hpp> */
#define HAVE_BOOST_SYSTEM_ERROR_CODE_HPP 1

/* Define to 1 if you have the `clock_gettime' function. */
#define HAVE_CLOCK_GETTIME 1

/* Define to 1 if you have the <crt_externs.h> header file. */
/* #undef HAVE_CRT_EXTERNS_H */

/* Define to 1 if you have the <crypto_scalarmult_curve25519.h> header file.
   */
/* #undef HAVE_CRYPTO_SCALARMULT_CURVE25519_H */

/* Define to 1 if you have the <cygwin/signal.h> header file. */
/* #undef HAVE_CYGWIN_SIGNAL_H */

/* Define to 1 if you have the declaration of `mlockall', and to 0 if you
   don't. */
#define HAVE_DECL_MLOCKALL 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <dmalloc.h> header file. */
/* #undef HAVE_DMALLOC_H */

/* Define to 1 if you have the `dmalloc_strdup' function. */
/* #undef HAVE_DMALLOC_STRDUP */

/* Define to 1 if you have the `dmalloc_strndup' function. */
/* #undef HAVE_DMALLOC_STRNDUP */

/* Define to 1 if you have the <errno.h> header file. */
#define HAVE_ERRNO_H 1

/* Define to 1 if you have the `evdns_set_outgoing_bind_address' function. */
/* #undef HAVE_EVDNS_SET_OUTGOING_BIND_ADDRESS */

/* Define to 1 if you have the <event2/bufferevent_ssl.h> header file. */
#define HAVE_EVENT2_BUFFEREVENT_SSL_H 1

/* Define to 1 if you have the <event2/dns.h> header file. */
#define HAVE_EVENT2_DNS_H 1

/* Define to 1 if you have the <event2/event.h> header file. */
#define HAVE_EVENT2_EVENT_H 1

/* Define to 1 if you have the `event_base_loopexit' function. */
#define HAVE_EVENT_BASE_LOOPEXIT 1

/* Define