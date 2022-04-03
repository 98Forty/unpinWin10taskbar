/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file address.c
 * \brief Functions to use and manipulate the tor_addr_t structure.
 **/

#include "orconfig.h"
#include "tor_compat.h"
#include "tor_util.h"
#include "address.h"
#include "torlog.h"
#include "container.h"
#include "sandbox.h"

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#include <winsock2.h>
/* For access to structs needed by GetAdaptersAddresses */
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#include <iphlpapi.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* FreeBSD needs this to know what version it is */
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* tor_addr_is_null() and maybe other functions rely on AF_UNSPEC being 0 to
 * work correctly. Bail out here if we've found a platform where AF_UNSPEC
 * isn't 0. */
#if AF_UNSPEC != 0
#error We rely on AF_UNSPEC being 0. Let us know about your platform, please!
#endif

/** Convert the tor_addr_t in <b>a</b>, with port in <b>port</b>, into a
 * sockaddr object in *<b>sa_out</b> of object size <b>len</b>.  If not enough
 * room is available in sa_out, or on error, return 0.  On success, return
 * the length of the sockaddr.
 *
 * Interface note: ordinarily, we return -1 for error.  We can't do that here,
 * since socklen_t is unsigned on some platforms.
 **/
socklen_t
tor_addr_to_sockaddr(const tor_addr_t *a,
                     uint16_t port,
                     struct sockaddr *sa_out,
                     socklen_t len)
{
  sa_family_t family = tor_addr_family(a);
  if (family == AF_INET) {
    struct sockaddr_in *sin;
    if (len < (int)sizeof(struct sockaddr_in))
      return 0;
    sin = (struct sockaddr_in *)sa_out;
    memset(sin, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
    sin->sin_len = sizeof(struct sockaddr_in);
#endif
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    sin->sin_addr.s_addr = tor_addr_to_ipv4n(a);
    return sizeof(struct sockaddr_in);
  } else if (family == AF_INET6) {
    struct sockaddr_in6 *sin6;
    if (len < (int)sizeof(struct sockaddr_in6))
      return 0;
    sin6 = (struct sockaddr_in6 *)sa_out;
    memset(sin6, 0, sizeof(struct sockaddr_in6));
#ifdef HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN
    sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons(port);
    memcpy(&sin6->sin6_addr, tor_addr_to_in6(a), sizeof(struct in6_addr));
    return sizeof(struct sockaddr_in6);
  } else {
    return 0;
  }
}

/** Set the tor_addr_t in <b>a</b> to contain the socket address contained in
 * <b>sa</b>. */
int
tor_addr_from_sockaddr(tor_addr_t *a, const struct sockaddr *sa,
                       uint16_t *port_out)
{
  tor_assert(a);
  tor_assert(sa);
  if (sa->sa_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *) sa;
    tor_addr_from_ipv4n(a, sin->sin_addr.s_addr);
    if (port_out)
      *port_out = ntohs(sin->sin_port);
  } else if (sa->sa_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
    tor_addr_from_in6(a, &sin6->sin6_addr);
    if (port_out)
      *port_out = ntohs(sin6->sin6_port);
  } else {
    tor_addr_make_unspec(a);
    return -1;
  }
  return 0;
}

/** Return a newly allocated string holding the address described in
 * <b>sa</b>.  AF_UNIX, AF_UNSPEC, AF_INET, and AF_INET6 are supported. */
char *
tor_sockaddr_to_str(const struct sockaddr *sa)
{
  char address[TOR_ADDR_BUF_LEN];
  char *result;
  tor_addr_t addr;
  uint16_t port;
#ifdef HAVE_SYS_UN_H
  if (sa->sa_family == AF_UNIX) {
    struct sockaddr_un *s_un = (struct sockaddr_un *)sa;
    tor_asprintf(&result, "unix:%s", s_un->sun_path);
    return result;
  }
#endif
  if (sa->sa_family == AF_UNSPEC)
    return tor_strdup("unspec");

  if (tor_addr_from_sockaddr(&addr, sa, &port) < 0)
    return NULL;
  if (! tor_addr_to_str(address, &addr, sizeof(address), 1))
    return NULL;
  tor_asprintf(&result, "%s:%d", address, (int)port);
  return result;
}

/** Set address <b>a</b> to the unspecified address.  This address belongs to
 * no family. */
void
tor_addr_make_unspec(tor_addr_t *a)
{
  memset(a, 0, sizeof(*a));
  a->family = AF_UNSPEC;
}

/** Set address <a>a</b> to the null address in address family <b>family</b>.
 * The null address for AF_INET is 0.0.0.0.  The null address for AF_INET6 is
 * [::].  AF_UNSPEC is all null. */
void
tor_addr_make_null(tor_addr_t *a, sa_family_t family)
{
  memset(a, 0, sizeof(*a));
  a->family = family;
}

/** Similar behavior to Unix gethostbyname: resolve <b>name</b>, and set
 * *<b>addr</b> to the proper IP address and family. The <b>family</b>
 * argument (which must be AF_INET, AF_INET6, or AF_UNSPEC) declares a
 * <i>preferred</i> family, though another one may be returned if only one
 * family is implemented for this address.
 *
 * Return 0 on success, -1 on failure; 1 on transient failure.
 */
int
tor_addr_lookup(const char *name, uint16_t family, tor_addr_t *addr)
{
  /* Perhaps eventually this should be replaced by a tor_getaddrinfo or
   * something.
   */
  struct in_addr iaddr;
  struct in6_addr iaddr6;
  tor_assert(name);
  tor_assert(addr);
  tor_assert(family == AF_INET || family == AF_INET6 || family == AF_UNSPEC);
  if (!*name) {
    /* Empty address is an error. */
    return -1;
  } else if (tor_inet_pton(AF_INET, name, &iaddr)) {
    /* It's an IPv4 IP. */
    if (family == AF_INET6)
      return -1;
    tor_addr_from_in(addr, &iaddr);
    return 0;
  } else if (tor_inet_pton(AF_INET6, name, &iaddr6)) {
    if (family == AF_INET)
      return -1;
    tor_addr_from_in6(addr, &iaddr6);
    return 0;
  } else {
#ifdef HAVE_GETADDRINFO
    int err;
    struct addrinfo *res=NULL, *res_p;
    struct addrinfo *best=NULL;
    struct addrinfo hints;
    int result = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    err = sandbox_getaddrinfo(name, NULL, &hints, &res);
    if (!err) {
      best = NULL;
      for (res_p = res; res_p; res_p = res_p->ai_next) {
        if (family == AF_UNSPEC) {
          if (res_p->ai_family == AF_INET) {
            best = res_p;
            break;
          } else if (res_p->ai_family == AF_INET6 && !best) {
            best = res_p;
          }
        } else if (family == res_p->ai_family) {
          best = res_p;
          break;
        }
      }
      if (!best)
        best = res;
      if (best->ai_family == AF_INET) {
        tor_addr_from_in(addr,
                         &((struct sockaddr_in*)best->ai_addr)->sin_addr);
        result = 0;
      } else if (best->ai_family == AF_INET6) {
        tor_addr_from_in6(addr,
                          &((struct sockaddr_in6*)best->ai_addr)->sin6_addr);
        result = 0;
      }
      freeaddrinfo(res);
      return result;
    }
    return (err == EAI_AGAIN) ? 1 : -1;
#else
    struct hostent *ent;
    int err;
#ifdef HAVE_GETHOSTBYNAME_R_6_ARG
    char buf[2048];
    struct hostent hostent;
    int r;
    r = gethostbyname_r(name, &hostent, buf, sizeof(buf), &ent, &err);
#elif defined(HAVE_GETHOSTBYNAME_R_5_ARG)
    char buf[2048];
    struct hostent hostent;
    ent = gethostbyname_r(name, &hostent, buf, sizeof(buf), &err);
#elif defined(HAVE_GETHOSTBYNAME_R_3_ARG)
    struct hostent_data data;
    struct hostent hent;
    memset(&data, 0, sizeof(data));
    err = gethostbyname_r(name, &hent, &data);
    ent = err ? NULL : &hent;
#else
    ent = gethostbyname(name);
#ifdef _WIN32
    err = WSAGetLastError();
#else
    err = h_errno;
#endif
#endif /* endif HAVE_GETHOSTBYNAME_R_6_ARG. */
    if (ent) {
      if (ent->h_addrtype == AF_INET) {
        tor_addr_from_in(addr, (struct in_addr*) ent->h_addr);
      } else if (ent->h_addrtype == AF_INET6) {
        tor_addr_from_in6(addr, (struct in6_addr*) ent->h_addr);
      } else {
        tor_assert(0); /* gethostbyname() returned a bizarre addrtype */
      }
      return 0;
    }
#ifdef _WIN32
    return (err == WSATRY_AGAIN) ? 1 : -1;
#else
    return (err == TRY_AGAIN) ? 1 