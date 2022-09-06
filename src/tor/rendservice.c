/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rendservice.c
 * \brief The hidden-service side of rendezvous functionality.
 **/

#define RENDSERVICE_PRIVATE

#include "or.h"
#include "circpathbias.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "config.h"
#include "directory.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "rendclient.h"
#include "rendcommon.h"
#include "rendservice.h"
#include "router.h"
#include "relay.h"
#include "rephist.h"
#include "replaycache.h"
#include "routerlist.h"
#include "routerparse.h"
#include "routerset.h"
#include "xdecoin.h"

static origin_circuit_t *find_intro_circuit(rend_intro_point_t *intro,
                                            const char *pk_digest);
static rend_intro_point_t *find_intro_point(origin_circuit_t *circ);

static extend_info_t *find_rp_for_intro(
    const rend_intro_cell_t *intro,
    uint8_t *need_free_out, char **err_msg_out);

static int intro_point_accepted_intro_count(rend_intro_point_t *intro);
static int intro_point_should_expire_now(rend_intro_point_t *intro,
                                         time_t now);
struct rend_service_t;
static int rend_service_load_keys(struct rend_service_t *s);
static int rend_service_load_auth_keys(struct rend_service_t *s,
                                       const char *hfname);

static ssize_t rend_service_parse_intro_for_v0_or_v1(
    rend_intro_cell_t *intro,
    const uint8_t *buf,
    size_t plaintext_len,
    char **err_msg_out);
static ssize_t rend_service_parse_intro_for_v2(
    rend_intro_cell_t *intro,
    const uint8_t *buf,
    size_t plaintext_len,
    char **err_msg_out);
static ssize_t rend_service_parse_intro_for_v3(
    rend_intro_cell_t *intro,
    const uint8_t *buf,
    size_t plaintext_len,
    char **err_msg_out);

/** Represents the mapping from a virtual port of a rendezvous service to
 * a real port on some IP.
 */
typedef struct rend_service_port_config_t {
  uint16_t virtual_port;
  uint16_t real_port;
  tor_addr_t real_addr;
} rend_service_port_config_t;

/** Try to maintain this many intro points per service by default. */
#define NUM_INTRO_POINTS_DEFAULT 3
/** Maintain no more than this many intro points per hidden service. */
#define NUM_INTRO_POINTS_MAX 10

/** If we can't build our intro circuits, don't retry for this long. */
#define INTRO_CIRC_RETRY_PERIOD (60*5)
/** Don't try to build more than this many circuits before giving up
 * for a while.*/
#define MAX_INTRO_CIRCS_PER_PERIOD 10
/** How many times will a hidden service operator attempt to connect to
 * a requested rendezvous point before giving up? */
#define MAX_REND_FAILURES 30
/** How many seconds should we spend trying to connect to a requested
 * rendezvous point before giving up? */
#define MAX_REND_TIMEOUT 30

/** How many seconds should we wait for new HS descriptors to reach
 * our clients before we close an expiring intro point? */
#define INTRO_POINT_EXPIRATION_GRACE_PERIOD (5*60)

/** Represents a single hidden service running at this OP. */
typedef struct rend_service_t {
  /* Fields specified in config file */
  char *directory; /**< where in the filesystem it stores it */
  smartlist_t *ports; /**< List of rend_service_port_config_t */
  rend_auth_type_t auth_type; /**< Client authorization type or 0 if no client
                               * authorization is performed. */
  smartlist_t *clients; /**< List of rend_authorized_client_t's of
                         * clients that may access our service. Can be NULL
                         * if no client authorization is performed. */
  /* Other fields */
  crypto_pk_t *private_key; /**< Permanent hidden-service key. */
  char service_id[REND_SERVICE_ID_LEN_BASE32+1]; /**< Onion address without
                                                  * '.onion' */
  char pk_digest[DIGEST_LEN]; /**< Hash of permanent hidden-service key. */
  smartlist_t *intro_nodes; /**< List of rend_intro_point_t's we have,
                             * or are trying to establish. */
  time_t intro_period_started; /**< Start of the current period to build
                                * introduction points. */
  int n_intro_circuits_launched; /**< Count of intro circuits we have
                                  * established in this period. */
  unsigned int n_intro_points_wanted; /**< Number of intro points this
                                       * service wants to have open. */
  rend_service_descriptor_t *desc; /**< Current hidden service descriptor. */
  time_t desc_is_dirty; /**< Time at which changes to the hidden service
                         * descriptor content occurred, or 0 if it's
                         * up-to-date. */
  time_t next_upload_time; /**< Scheduled next hidden service descriptor
                            * upload time. */
  /** Replay cache for Diffie-Hellman values of INTRODUCE2 cells, to
   * detect repeats.  Clients may send INTRODUCE1 cells for the same
   * rendezvous point through two or more different introduction points;
   * when they do, this keeps us from launching multiple simultaneous attempts
   * to connect to the same rend point. */
  replaycache_t *accepted_intro_dh_parts;
} rend_service_t;

/** A list of rend_service_t's for services run on this OP.
 */
static smartlist_t *rend_service_list = NULL;

/** Return the number of rendezvous services we have configured. */
int
num_rend_services(void)
{
  if (!rend_service_list)
    return 0;
  return smartlist_len(rend_service_list);
}

/** Return a string identifying <b>service</b>, suitable for use in a
 * log message.  The result does not need to be freed, but may be
 * overwritten by the next call to this function. */
static const char *
rend_service_describe_for_log(rend_service_t *service)
{
  /* XXX024 Use this function throughout rendservice.c. */
  /* XXX024 Return a more useful description? */
  return safe_str_client(service->service_id);
}

/** Helper: free storage held by a single service authorized client entry. */
static void
rend_authorized_client_free(rend_authorized_client_t *client)
{
  if (!client)
    return;
  if (client->client_key)
    crypto_pk_free(client->client_key);
  tor_strclear(client->client_name);
  tor_free(client->client_name);
  memwipe(client->descriptor_cookie, 0, sizeof(client->descriptor_cookie));
  tor_free(client);
}

/** Helper for strmap_free. */
static void
rend_authorized_client_strmap_item_free(void *authorized_client)
{
  rend_authorized_client_free(authorized_client);
}

/** Release the storage held by <b>service</b>.
 */
static void
rend_service_free(rend_service_t *service)
{
  if (!service)
    return;

  tor_free(service->directory);
  SMARTLIST_FOREACH(service->ports, void*, p, tor_free(p));
  smartlist_free(service->ports);
  if (service->private_key)
    crypto_pk_free(service->private_key);
  if (service->intro_nodes) {
    SMARTLIST_FOREACH(service->intro_nodes, rend_intro_point_t *, intro,
      rend_intro_point_free(intro););
    smartlist_free(service->intro_nodes);
  }

  rend_service_descriptor_free(service->desc);
  if (service->clients) {
    SMARTLIST_FOREACH(service->clients, rend_authorized_client_t *, c,
      rend_authorized_client_free(c););
    smartlist_free(service->clients);
  }
  if (service->accepted_intro_dh_parts) {
    replaycache_free(service->accepted_intro_dh_parts);
  }
  tor_free(service);
}

/** Release all the storage held in rend_service_list.
 */
void
rend_service_free_all(void)
{
  if (!rend_service_list)
    return;

  SMARTLIST_FOREACH(rend_service_list, rend_service_t*, ptr,
                    rend_service_free(ptr));
  smartlist_free(rend_service_list);
  rend_service_list = NULL;
}

/** Validate <b>service</b> and add it to rend_service_list if possible.
 */
static void
rend_add_service(rend_service_t *service)
{
  int i;
  rend_service_port_config_t *p;

  service->intro_nodes = smartlist_new();

  if (service->auth_type != REND_NO_AUTH &&
      smartlist_len(service->clients) == 0) {
    log_warn(LD_CONFIG, "Hidden service (%s) with client authorization but no "
                        "clients; ignoring.",
             escaped(service->directory));
    rend_service_free(service);
    return;
  }

  if (!smartlist_len(service->ports)) {
    log_warn(LD_CONFIG, "Hidden service (%s) with no ports configured; "
             "ignoring.",
             escaped(service->directory));
    rend_service_free(service);
  } else {
    int dupe = 0;
    /* XXX This duplicate check has two problems:
     *
     * a) It's O(n^2), but the same comment from the bottom of
     *    rend_config_services() should apply.
     *
     * b) We only compare directory paths as strings, so we can't
     *    detect two distinct paths that specify the same directory
     *    (which can arise from symlinks, case-insensitivity, bind
     *    mounts, etc.).
     *
     * It also can't detect that two separate Tor instances are trying
     * to use the same HiddenServiceDir; for that, we would need a
     * lock file.  But this is enough to detect a simple mistake that
     * at least one person has actually made.
     */
    SMARTLIST_FOREACH(rend_service_list, rend_service_t*, ptr,
                      dupe = dupe ||
                             !strcmp(ptr->directory, service->directory));
    if (dupe) {
      log_warn(LD_REND, "Another hidden service is already configured for "
               "directory %s, ignoring.", service->directory);
      rend_service_free(service);
      return;
    }
    smartlist_add(rend_service_list, service);
    log_debug(LD_REND,"Configuring service with directory \"%s\"",
              service->directory);
    for (i = 0; i < smartlist_len(service->ports); ++i) {
      p = smartlist_get(service->ports, i);
      log_debug(LD_REND,"Service maps port %d to %s",
                p->virtual_port, fmt_addrport(&p->real_addr, p->real_port));
    }
  }
}

/** Parses a real-port to virtual-port mapping and returns a new
 * rend_service_port_config_t.
 *
 * The format is: VirtualPort (IP|RealPort|IP:RealPort)?
 *
 * IP defaults to 127.0.0.1; RealPort defaults to VirtualPort.
 */
static rend_service_port_config_t *
parse_port_config(const char *string)
{
  smartlist_t *sl;
  int virtport;
  int realport;
  uint16_t p;
  tor_addr_t addr;
  const char *addrport;
  rend_service_port_config_t *result = NULL;

  sl = smartlist_new();
  smartlist_split_string(sl, string, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  if (smartlist_len(sl) < 1 || smartlist_len(sl) > 2) {
    log_warn(LD_CONFIG, "Bad syntax in hidden service port configuration.");
    goto err;
  }

  virtport = (int)tor_parse_long(smartlist_get(sl,0), 10, 1, 65535, NULL,NULL);
  if (!virtport) {
    log_warn(LD_CONFIG, "Missing or invalid port %s in hidden service port "
             "configuration", escaped(smartlist_get(sl,0)));
    goto err;
  }

  if (smartlist_len(sl) == 1) {
    /* No addr:port part; use default. */
    realport = virtport;
    tor_addr_from_ipv4h(&addr, 0x7F000001u); /* 127.0.0.1 */
  } else {
    addrport = smartlist_get(sl,1);
    if (strchr(addrport, ':') || strchr(addrport, '.')) {
      if (tor_addr_port_lookup(addrport, &addr, &p)<0) {
        log_warn(LD_CONFIG,"Unparseable address in hidden service port "
                 "configuration.");
        goto err;
      }
      realport = p?p:virtport;
    } else {
      /* No addr:port, no addr -- must be port. */
      realport = (int)tor_parse_long(addrport, 10, 1, 65535, NULL, NULL);
      if (!realport) {
     