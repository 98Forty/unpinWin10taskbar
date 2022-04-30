/* Copyright (c) 2009-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_COMPAT_LIBEVENT_H
#define TOR_COMPAT_LIBEVENT_H

#include "orconfig.h"

struct event;
struct event_base;
#ifdef USE_BUFFEREVENTS
struct bufferevent;
struct ev_token_bucket_cfg;
struct bufferevent_rate_limit_group;
#endif

#ifdef HAVE_EVENT2_EVENT_H
#include <event2/util.h>
#elif !defined(EVUTIL_SOCKET_DEFINED)
#define EVUTIL_SOCKET_DEFINED
#define evutil_socket_t int
#endif

void configure_libevent_logging(void);
void suppress_libevent_log_msg(const char *msg);

#ifdef HAVE_EVENT2_EVENT_H
#define tor_event_new     event_new
#define tor_evtimer_new   evtimer_new
#define tor_evsignal_new  evsignal_new
#define tor_event_free    event_free
#define tor_evdns_add_server_port(sock, tcp, cb, data) \
  evdns