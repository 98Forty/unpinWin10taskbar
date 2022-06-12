/* Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dnsserv.c \brief Implements client-side DNS proxy server code.  Note:
 * this is the DNS Server code, not the Server DNS code.  Confused?  This code
 * runs on client-side, and acts as a DNS server.  The code in dns.c, on the
 * other hand, runs on Tor servers, and acts as a DNS client.
 **/

#include "or.h"
#include "dnsserv.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "control.h"
#include "onion_main.h"
#include "policies.h"
#ifdef HAVE_EVENT2_DNS_H
#include <event2/dns.h>
#include <event2/dns_compat.h>
/* XXXX this implies we want an improved evdns  */
#include <event2/dns_struct.h>
#else
#include "eventdns.h"
#endif

/** Helper function: called by evdns whenever the client sends a request to our
 * DNSPort.  We need to eventually answer the request <b>req</b>.
 */
static void
evdns_server_callback(struct evdns_server_request *req, void *data_)
{
  const listener_connection_t *listener = data_;
  entry_connection_t *entry_conn;
  edge_connection_t *conn;
  int i = 0;
  struct evdns_server_question *q = NULL;
  struct sockaddr_storage addr;
  struct sockaddr *sa;
  int addrlen;
  tor_addr_t tor_addr;
  uint16_t port;
  int err = DNS_ERR_NONE;
  char *q_name;

  tor_assert(req);

  log_info(LD_APP, "Got a new DNS request!");

  req->flags |= 0x80; /* set RA */

  /* First, check whether the requesting address matches our SOCKSPolicy. */
  if ((addrlen = evdns_server_request_get_requesting_addr(req,
                      (struct sockaddr*)&addr, (socklen_t)sizeof(addr))) < 0) {
    log_warn(LD_APP, "Couldn't get requesting address.");
    evdns_server_request_respond(req, DNS_ERR_SERVERFAILED);
    return;
  }
  (void) addrlen;
  sa = (struct sockaddr*) &addr;
  if (tor_addr_from_sockaddr(&tor_addr, sa, &port)<0) {
    log_warn(LD_APP, "Requesting address wasn't recognized.");
    evdns_server_request_respond(req, DNS_ERR_SERVERFAILED);
    return;
  }

  if (!socks_policy_permits_address(&tor_addr)) {
    log_warn(LD_APP, "Rejecting DNS request from disallowed IP.");
    evdns_server_request_respond(req, DNS_ERR_REFUSED);
    return;
  }

  /* Now, let's find the first actual question of a type we can answer in this
   * DNS request.  It makes us a little noncompliant to act like this; we
   * should fix that eventually if it turns out to make a difference for
   * anybody. */
  if (req->nquestions == 0) {
    log_info(LD_APP, "No questions in DNS request; sending back nil reply.");
    evdns_server_request_respond(req, 0);
    return;
  }
  if (req->nquestions > 1) {
    log_info(LD_APP, "Got a DNS request with more than one question; I only "
             "handle one question at a time for now.  Skipping the extras.");
  }
  for (i = 0; i < req->nquestions; ++i) {
    if (req->questions[i]->dns_question_class != EVDNS_CLASS_INET)
      continue;
    switch (req->questions[i]->type) {
      case EVDNS_TYPE_A:
      case EVDNS_TYPE_AAAA:
      case EVDNS_TYPE_PTR:
        q = req->questions[i];
      default:
        break;
      }
  }
  if (!q) {
    log_info(LD_APP, "None of the questions we got were ones we're willing "
             "to support. Sending NOTIMPL.");
    evdns_server_request_respond(req, DNS_ERR_NOTIMPL);
    return;
  }
  if (q->type != EVDNS_TYPE_A && q->type != EVDNS_TYPE_AAAA) {
    tor_assert(q->type == EVDNS_TYPE_PTR);
  }

  /* Make sure the name isn't too long: This should be impossible, I think. */
  if (err == DNS_ERR_NONE && strlen(q->name) > MAX_SOCKS_ADDR_LEN-1)
    err = DNS_ERR_FORMAT;

  if (err != DNS_ERR_NONE) {
    /* We got an error?  Then send back an answer immediately; we're done. */
    evdns_server_request_respond(req, err);
    return;
  }

  /* Make a new dummy AP connection, and attach the request to it. */
  entry_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  conn = ENTRY_TO_EDGE_CONN(entry_conn);
  TO_CONN(conn)->state = AP_CONN_STATE_RESOLVE_WAIT;
  conn->is_dns_request = 1;

  tor_addr_copy(&TO_CONN(conn)->addr, &tor_addr);
  TO_CONN(conn)->port = port;
  TO_CONN(conn)->address = tor_dup_addr(&tor_addr);

  if (q->type == EVDNS_TYPE_A || q->type == EVDNS_TYPE_AAAA)
    entry_conn->socks_request->command = SOCKS_COMMAND_RESOLVE;
  else
    entry_conn->socks_request->command = SOCKS_COMMAND_RESOLVE_PTR;

  strlcpy(entry_conn->socks_request->address, q->name,
          sizeof(entry_conn->socks_request->address));

  entry_conn->socks_request->listener_type = listener->base_.type;
  entry_conn->dns_server_request = req;
  entry_conn->isolation_flags = listener->isolation_flags;
  entry_conn->session_group = listener->session_group;
  entry_conn->nym_epoch = get_signewnym_epoch();

  if (connection_add(ENTRY_TO_CONN(entry_conn)) < 0) {
    log_warn(LD_APP, "Couldn't register dummy connection for DNS request");
    evdns_server_request_respond(req, DNS_ERR_SERVERFAILED);
    connection_free(ENTRY_TO_CONN(entry_conn));
    return;
  }

  control_event_stream_status(entry_conn, STREAM_EVENT_NEW_RESOLVE, 0);

  /* Now, unless a controller asked us to leave streams unattached,
  * throw the connection over to get rewritten (which will
  * answer it immediately if it's in the cache, or completely bogus, or
  * automapped), and then attached to a circuit. */
  log_info(LD_APP, "Passing request for %s to rewrite_and_attach.",
           escaped_safe_str_client(q->name));
  q_name = tor_strdup(q->name); /* q could be freed in rewrite_and_attach */
  connection_ap_rewrite_and_attach_if_allowed(entry_conn, NULL, NULL);
  /* Now, the connection is marked if it was bad. */

  log_info(LD_APP, "Passed request for %s to rewrite_and_attach_if_allowed.",
           escaped_safe_str_client(q_name));
  tor_free(q_name);
}

/** Helper function: called whenever the client sends a resolve request to our
 * controller.  We need to eventually answer the request <b>req</b>.
 * Returns 0 if the controller will be getting (or has gotten) an event in
 * response; -1 if we couldn't launch the request.
 */
int
dnsserv_launch_request(const char *name, int reverse,
                       control_connection_t *control_conn)
{
  entry_connection_t *entry_conn;
  edge_connection_t *conn;
  char *q_name;

  /* Make a new dummy AP connection, and attach the request to it. */
  entry_conn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  conn = ENTRY_TO_EDGE_CONN(entry_conn);
  conn->base_.state = AP_CONN_STATE_RESOLVE_WAIT;

  tor_addr_copy(&TO_CONN(conn)->addr, &control_conn->base_.addr);
#ifdef AF_UNIX
  /*
   * The control connection can be