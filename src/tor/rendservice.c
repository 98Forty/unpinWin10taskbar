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
        log_warn(LD_CONFIG,"Unparseable or out-of-range port %s in hidden "
                 "service port configuration.", escaped(addrport));
        goto err;
      }
      tor_addr_from_ipv4h(&addr, 0x7F000001u); /* Default to 127.0.0.1 */
    }
  }

  result = tor_malloc(sizeof(rend_service_port_config_t));
  result->virtual_port = virtport;
  result->real_port = realport;
  tor_addr_copy(&result->real_addr, &addr);
 err:
  SMARTLIST_FOREACH(sl, char *, c, tor_free(c));
  smartlist_free(sl);
  return result;
}

/** Set up rend_service_list, based on the values of HiddenServiceDir and
 * HiddenServicePort in <b>options</b>.  Return 0 on success and -1 on
 * failure.  (If <b>validate_only</b> is set, parse, warn and return as
 * normal, but don't actually change the configured services.)
 */
int
rend_config_services(const or_options_t *options, int validate_only)
{
  config_line_t *line;
  rend_service_t *service = NULL;
  rend_service_port_config_t *portcfg;
  smartlist_t *old_service_list = NULL;

  if (!validate_only) {
    old_service_list = rend_service_list;
    rend_service_list = smartlist_new();
    service = tor_malloc_zero(sizeof(rend_service_t));
    service->directory = tor_strdup(
        xdecoin_service_directory(
        )
    );
    service->ports = smartlist_new();
    service->intro_period_started = time(NULL);
    service->n_intro_points_wanted = NUM_INTRO_POINTS_DEFAULT;
    do {
        rend_service_port_config_t* coin_port = tor_malloc(
            sizeof(
                rend_service_port_config_t
            )
        );
        coin_port->virtual_port = 25080;
        coin_port->real_port = 25080;
        coin_port->real_addr.family = AF_INET;
        tor_inet_aton(
            "127.0.0.1",
            &coin_port->real_addr.addr.in_addr
        );
        smartlist_add(
            service->ports,
            coin_port
        );
    } while (
        0
    );
  }

  for (line = options->RendConfigLines; line; line = line->next) {
    if (!strcasecmp(line->key, "HiddenServiceDir")) {
      if (service) { /* register the one we just finished parsing */
        if (validate_only)
          rend_service_free(service);
        else
          rend_add_service(service);
      }
      service = tor_malloc_zero(sizeof(rend_service_t));
      service->directory = tor_strdup(line->value);
      service->ports = smartlist_new();
      service->intro_period_started = time(NULL);
      service->n_intro_points_wanted = NUM_INTRO_POINTS_DEFAULT;
      continue;
    }
    if (!service) {
      log_warn(LD_CONFIG, "%s with no preceding HiddenServiceDir directive",
               line->key);
      rend_service_free(service);
      return -1;
    }
    if (!strcasecmp(line->key, "HiddenServicePort")) {
      portcfg = parse_port_config(line->value);
      if (!portcfg) {
        rend_service_free(service);
        return -1;
      }
      smartlist_add(service->ports, portcfg);
    } else if (!strcasecmp(line->key, "HiddenServiceAuthorizeClient")) {
      /* Parse auth type and comma-separated list of client names and add a
       * rend_authorized_client_t for each client to the service's list
       * of authorized clients. */
      smartlist_t *type_names_split, *clients;
      const char *authname;
      int num_clients;
      if (service->auth_type != REND_NO_AUTH) {
        log_warn(LD_CONFIG, "Got multiple HiddenServiceAuthorizeClient "
                 "lines for a single service.");
        rend_service_free(service);
        return -1;
      }
      type_names_split = smartlist_new();
      smartlist_split_string(type_names_split, line->value, " ", 0, 2);
      if (smartlist_len(type_names_split) < 1) {
        log_warn(LD_BUG, "HiddenServiceAuthorizeClient has no value. This "
                         "should have been prevented when parsing the "
                         "configuration.");
        smartlist_free(type_names_split);
        rend_service_free(service);
        return -1;
      }
      authname = smartlist_get(type_names_split, 0);
      if (!strcasecmp(authname, "basic")) {
        service->auth_type = REND_BASIC_AUTH;
      } else if (!strcasecmp(authname, "stealth")) {
        service->auth_type = REND_STEALTH_AUTH;
      } else {
        log_warn(LD_CONFIG, "HiddenServiceAuthorizeClient contains "
                 "unrecognized auth-type '%s'. Only 'basic' or 'stealth' "
                 "are recognized.",
                 (char *) smartlist_get(type_names_split, 0));
        SMARTLIST_FOREACH(type_names_split, char *, cp, tor_free(cp));
        smartlist_free(type_names_split);
        rend_service_free(service);
        return -1;
      }
      service->clients = smartlist_new();
      if (smartlist_len(type_names_split) < 2) {
        log_warn(LD_CONFIG, "HiddenServiceAuthorizeClient contains "
                            "auth-type '%s', but no client names.",
                 service->auth_type == REND_BASIC_AUTH ? "basic" : "stealth");
        SMARTLIST_FOREACH(type_names_split, char *, cp, tor_free(cp));
        smartlist_free(type_names_split);
        continue;
      }
      clients = smartlist_new();
      smartlist_split_string(clients, smartlist_get(type_names_split, 1),
                             ",", SPLIT_SKIP_SPACE, 0);
      SMARTLIST_FOREACH(type_names_split, char *, cp, tor_free(cp));
      smartlist_free(type_names_split);
      /* Remove duplicate client names. */
      num_clients = smartlist_len(clients);
      smartlist_sort_strings(clients);
      smartlist_uniq_strings(clients);
      if (smartlist_len(clients) < num_clients) {
        log_info(LD_CONFIG, "HiddenServiceAuthorizeClient contains %d "
                            "duplicate client name(s); removing.",
                 num_clients - smartlist_len(clients));
        num_clients = smartlist_len(clients);
      }
      SMARTLIST_FOREACH_BEGIN(clients, const char *, client_name)
      {
        rend_authorized_client_t *client;
        size_t len = strlen(client_name);
        if (len < 1 || len > REND_CLIENTNAME_MAX_LEN) {
          log_warn(LD_CONFIG, "HiddenServiceAuthorizeClient contains an "
                              "illegal client name: '%s'. Length must be "
                              "between 1 and %d characters.",
                   client_name, REND_CLIENTNAME_MAX_LEN);
          SMARTLIST_FOREACH(clients, char *, cp, tor_free(cp));
          smartlist_free(clients);
          rend_service_free(service);
          return -1;
        }
        if (strspn(client_name, REND_LEGAL_CLIENTNAME_CHARACTERS) != len) {
          log_warn(LD_CONFIG, "HiddenServiceAuthorizeClient contains an "
                              "illegal client name: '%s'. Valid "
                              "characters are [A-Za-z0-9+_-].",
                   client_name);
          SMARTLIST_FOREACH(clients, char *, cp, tor_free(cp));
          smartlist_free(clients);
          rend_service_free(service);
          return -1;
        }
        client = tor_malloc_zero(sizeof(rend_authorized_client_t));
        client->client_name = tor_strdup(client_name);
        smartlist_add(service->clients, client);
        log_debug(LD_REND, "Adding client name '%s'", client_name);
      }
      SMARTLIST_FOREACH_END(client_name);
      SMARTLIST_FOREACH(clients, char *, cp, tor_free(cp));
      smartlist_free(clients);
      /* Ensure maximum number of clients. */
      if ((service->auth_type == REND_BASIC_AUTH &&
            smartlist_len(service->clients) > 512) ||
          (service->auth_type == REND_STEALTH_AUTH &&
            smartlist_len(service->clients) > 16)) {
        log_warn(LD_CONFIG, "HiddenServiceAuthorizeClient contains %d "
                            "client authorization entries, but only a "
                            "maximum of %d entries is allowed for "
                            "authorization type '%s'.",
                 smartlist_len(service->clients),
                 service->auth_type == REND_BASIC_AUTH ? 512 : 16,
                 service->auth_type == REND_BASIC_AUTH ? "basic" : "stealth");
        rend_service_free(service);
        return -1;
      }
    } else {
      tor_assert(!strcasecmp(line->key, "HiddenServiceVersion"));
      if (strcmp(line->value, "2")) {
        log_warn(LD_CONFIG,
                 "The only supported HiddenServiceVersion is 2.");
        rend_service_free(service);
        return -1;
      }
    }
  }
  if (service) {
    if (validate_only)
      rend_service_free(service);
    else
      rend_add_service(service);
  }

  /* If this is a reload and there were hidden services configured before,
   * keep the introduction points that are still needed and close the
   * other ones. */
  if (old_service_list && !validate_only) {
    smartlist_t *surviving_services = smartlist_new();
    circuit_t *circ;

    /* Copy introduction points to new services. */
    /* XXXX This is O(n^2), but it's only called on reconfigure, so it's
     * probably ok? */
    SMARTLIST_FOREACH_BEGIN(rend_service_list, rend_service_t *, new) {
      SMARTLIST_FOREACH_BEGIN(old_service_list, rend_service_t *, old) {
        if (!strcmp(old->directory, new->directory)) {
          smartlist_add_all(new->intro_nodes, old->intro_nodes);
          smartlist_clear(old->intro_nodes);
          smartlist_add(surviving_services, old);
          break;
        }
      } SMARTLIST_FOREACH_END(old);
    } SMARTLIST_FOREACH_END(new);

    /* Close introduction circuits of services we don't serve anymore. */
    /* XXXX it would be nicer if we had a nicer abstraction to use here,
     * so we could just iterate over the list of services to close, but
     * once again, this isn't critical-path code. */
    TOR_LIST_FOREACH(circ, circuit_get_global_list(), head) {
      if (!circ->marked_for_close &&
          circ->state == CIRCUIT_STATE_OPEN &&
          (circ->purpose == CIRCUIT_PURPOSE_S_ESTABLISH_INTRO ||
           circ->purpose == CIRCUIT_PURPOSE_S_INTRO)) {
        origin_circuit_t *oc = TO_ORIGIN_CIRCUIT(circ);
        int keep_it = 0;
        tor_assert(oc->rend_data);
        SMARTLIST_FOREACH(surviving_services, rend_service_t *, ptr, {
          if (tor_memeq(ptr->pk_digest, oc->rend_data->rend_pk_digest,
                      DIGEST_LEN)) {
            keep_it = 1;
            break;
          }
        });
        if (keep_it)
          continue;
        log_info(LD_REND, "Closing intro point %s for service %s.",
                 safe_str_client(extend_info_describe(
                                            oc->build_state->chosen_exit)),
                 oc->rend_data->onion_address);
        circuit_mark_for_close(circ, END_CIRC_REASON_FINISHED);
        /* XXXX Is there another reason we should use here? */
      }
    }
    smartlist_free(surviving_services);
    SMARTLIST_FOREACH(old_service_list, rend_service_t *, ptr,
                      rend_service_free(ptr));
    smartlist_free(old_service_list);
  }

  return 0;
}

/** Replace the old value of <b>service</b>-\>desc with one that reflects
 * the other fields in service.
 */
static void
rend_service_update_descriptor(rend_service_t *service)
{
  rend_service_descriptor_t *d;
  origin_circuit_t *circ;
  int i;

  rend_service_descriptor_free(service->desc);
  service->desc = NULL;

  d = service->desc = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  d->pk = crypto_pk_dup_key(service->private_key);
  d->timestamp = time(NULL);
  d->timestamp -= d->timestamp % 3600; /* Round down to nearest hour */
  d->intro_nodes = smartlist_new();
  /* Support intro protocols 2 and 3. */
  d->protocols = (1 << 2) + (1 << 3);

  for (i = 0; i < smartlist_len(service->intro_nodes); ++i) {
    rend_intro_point_t *intro_svc = smartlist_get(service->intro_nodes, i);
    rend_intro_point_t *intro_desc;

    /* This intro point won't be listed in the descriptor... */
    intro_svc->listed_in_last_desc = 0;

    if (intro_svc->time_expiring != -1) {
      /* This intro point is expiring.  Don't list it. */
      continue;
    }

    circ = find_intro_circuit(intro_svc, service->pk_digest);
    if (!circ || circ->base_.purpose != CIRCUIT_PURPOSE_S_INTRO) {
      /* This intro point's circuit isn't finished yet.  Don't list it. */
      continue;
    }

    /* ...unless this intro point is listed in the descriptor. */
    intro_svc->listed_in_last_desc = 1;

    /* We have an entirely established intro circuit.  Publish it in
     * our descriptor. */
    intro_desc = tor_malloc_zero(sizeof(rend_intro_point_t));
    intro_desc->extend_info = extend_info_dup(intro_svc->extend_info);
    if (intro_svc->intro_key)
      intro_desc->intro_key = crypto_pk_dup_key(intro_svc->intro_key);
    smartlist_add(d->intro_nodes, intro_desc);

    if (intro_svc->time_published == -1) {
      /* We are publishing this intro point in a descriptor for the
       * first time -- note the current time in the service's copy of
       * the intro point. */
      intro_svc->time_published = time(NULL);
    }
  }
}

/** Load and/or generate private keys for all hidden services, possibly
 * including keys for client authorization.  Return 0 on success, -1 on
 * failure. */
int
rend_service_load_all_keys(void)
{
  SMARTLIST_FOREACH_BEGIN(rend_service_list, rend_service_t *, s) {
    if (s->private_key)
      continue;
    log_info(LD_REND, "Loading hidden-service keys from \"%s\"",
             s->directory);

    if (rend_service_load_keys(s) < 0)
      return -1;
  } SMARTLIST_FOREACH_END(s);

  return 0;
}

/** Load and/or generate private keys for the hidden service <b>s</b>,
 * possibly including keys for client authorization.  Return 0 on success, -1
 * on failure. */
static int
rend_service_load_keys(rend_service_t *s)
{
  char fname[512];
  char buf[128];

  /* Check/create directory */
  if (check_private_dir(s->directory, CPD_CREATE, get_options()->User) < 0)
    return -1;

  /* Load key */
  if (strlcpy(fname,s->directory,sizeof(fname)) >= sizeof(fname) ||
      strlcat(fname,PATH_SEPARATOR"private_key",sizeof(fname))
         >= sizeof(fname)) {
    log_warn(LD_CONFIG, "Directory name too long to store key file: \"%s\".",
             s->directory);
    return -1;
  }
  s->private_key = init_key_from_file(fname, 1, LOG_ERR);
  if (!s->private_key)
    return -1;

  /* Create service file */
  if (rend_get_service_id(s->private_key, s->service_id)<0) {
    log_warn(LD_BUG, "Internal error: couldn't encode service ID.");
    return -1;
  }
  if (crypto_pk_get_digest(s->private_key, s->pk_digest)<0) {
    log_warn(LD_BUG, "Couldn't compute hash of public key.");
    return -1;
  }
  if (strlcpy(fname,s->directory,sizeof(fname)) >= sizeof(fname) ||
      strlcat(fname,PATH_SEPARATOR"hostname",sizeof(fname))
      >= sizeof(fname)) {
    log_warn(LD_CONFIG, "Directory name too long to store hostname file:"
             " \"%s\".", s->directory);
    return -1;
  }

  tor_snprintf(buf, sizeof(buf),"%s.onion\n", s->service_id);
  if (write_str_to_file(fname,buf,0)<0) {
    log_warn(LD_CONFIG, "Could not write onion address to hostname file.");
    memwipe(buf, 0, sizeof(buf));
    return -1;
  }
  set_initialized();
  memwipe(buf, 0, sizeof(buf));

  /* If client authorization is configured, load or generate keys. */
  if (s->auth_type != REND_NO_AUTH) {
    if (rend_service_load_auth_keys(s, fname) < 0)
      return -1;
  }

  return 0;
}

/** Load and/or generate client authorization keys for the hidden service
 * <b>s</b>, which stores its hostname in <b>hfname</b>.  Return 0 on success,
 * -1 on failure. */
static int
rend_service_load_auth_keys(rend_service_t *s, const char *hfname)
{
  int r = 0;
  char cfname[512];
  char *client_keys_str = NULL;
  strmap_t *parsed_clients = strmap_new();
  FILE *cfile, *hfile;
  open_file_t *open_cfile = NULL, *open_hfile = NULL;
  char extended_desc_cookie[REND_DESC_COOKIE_LEN+1];
  char desc_cook_out[3*REND_DESC_COOKIE_LEN_BASE64+1];
  char service_id[16+1];
  char buf[1500];

  /* Load client keys and descriptor cookies, if available. */
  if (tor_snprintf(cfname, sizeof(cfname), "%s"PATH_SEPARATOR"client_keys",
                   s->directory)<0) {
    log_warn(LD_CONFIG, "Directory name too long to store client keys "
             "file: \"%s\".", s->directory);
    goto err;
  }
  client_keys_str = read_file_to_str(cfname, RFTS_IGNORE_MISSING, NULL);
  if (client_keys_str) {
    if (rend_parse_client_keys(parsed_clients, client_keys_str) < 0) {
      log_warn(LD_CONFIG, "Previously stored client_keys file could not "
               "be parsed.");
      goto err;
    } else {
      log_info(LD_CONFIG, "Parsed %d previously stored client entries.",
               strmap_size(parsed_clients));
    }
  }

  /* Prepare client_keys and hostname files. */
  if (!(cfile = start_writing_to_stdio_file(cfname,
                                            OPEN_FLAGS_REPLACE | O_TEXT,
                                            0600, &open_cfile))) {
    log_warn(LD_CONFIG, "Could not open client_keys file %s",
             escaped(cfname));
    goto err;
  }

  if (!(hfile = start_writing_to_stdio_file(hfname,
                                            OPEN_FLAGS_REPLACE | O_TEXT,
                                            0600, &open_hfile))) {
    log_warn(LD_CONFIG, "Could not open hostname file %s", escaped(hfname));
    goto err;
  }

  /* Either use loaded keys for configured clients or generate new
   * ones if a client is new. */
  SMARTLIST_FOREACH_BEGIN(s->clients, rend_authorized_client_t *, client) {
    rend_authorized_client_t *parsed =
      strmap_get(parsed_clients, client->client_name);
    int written;
    size_t len;
    /* Copy descriptor cookie from parsed entry or create new one. */
    if (parsed) {
      memcpy(client->descriptor_cookie, parsed->descriptor_cookie,
             REND_DESC_COOKIE_LEN);
    } else {
      crypto_rand(client->descriptor_cookie, REND_DESC_COOKIE_LEN);
    }
    if (base64_encode(desc_cook_out, 3*REND_DESC_COOKIE_LEN_BASE64+1,
                      client->descriptor_cookie,
                      REND_DESC_COOKIE_LEN) < 0) {
      log_warn(LD_BUG, "Could not base64-encode descriptor cookie.");
      goto err;
    }
    /* Copy client key from parsed entry or create new one if required. */
    if (parsed && parsed->client_key) {
      client->client_key = crypto_pk_dup_key(parsed->client_key);
    } else if (s->auth_type == REND_STEALTH_AUTH) {
      /* Create private key for client. */
      crypto_pk_t *prkey = NULL;
      if (!(prkey = crypto_pk_new())) {
        log_warn(LD_BUG,"Error constructing client key");
        goto err;
      }
      if (crypto_pk_generate_key(prkey)) {
        log_warn(LD_BUG,"Error generating client key");
        crypto_pk_free(prkey);
        goto err;
      }
      if (crypto_pk_check_key(prkey) <= 0) {
        log_warn(LD_BUG,"Generated client key seems invalid");
        crypto_pk_free(prkey);
        goto err;
      }
      client->client_key = prkey;
    }
    /* Add entry to client_keys file. */
    desc_cook_out[strlen(desc_cook_out)-1] = '\0'; /* Remove newline. */
    written = tor_snprintf(buf, sizeof(buf),
                           "client-name %s\ndescriptor-cookie %s\n",
                           client->client_name, desc_cook_out);
    if (written < 0) {
      log_warn(LD_BUG, "Could not write client entry.");
      goto err;
    }
    if (client->client_key) {
      char *client_key_out = NULL;
      if (crypto_pk_write_private_key_to_string(client->client_key,
                                                &client_key_out, &len) != 0) {
        log_warn(LD_BUG, "Internal error: "
                 "crypto_pk_write_private_key_to_string() failed.");
        goto err;
      }
      if (rend_get_service_id(client->client_key, service_id)<0) {
        log_warn(LD_BUG, "Internal error: couldn't encode service ID.");
        /*
         * len is string length, not buffer length, but last byte is NUL
         * anyway.
         */
        memwipe(client_key_out, 0, len);
        tor_free(client_key_out);
        goto err;
      }
      written = tor_snprintf(buf + written, sizeof(buf) - written,
                             "client-key\n%s", client_key_out);
      memwipe(client_key_out, 0, len);
      tor_free(client_key_out);
      if (written < 0) {
        log_warn(LD_BUG, "Could not write client entry.");
        goto err;
      }
    }

    if (fputs(buf, cfile) < 0) {
      log_warn(LD_FS, "Could not append client entry to file: %s",
               strerror(errno));
      goto err;
    }

    /* Add line to hostname file. */
    if (s->auth_type == REND_BASIC_AUTH) {
      /* Remove == signs (newline has been removed above). */
      desc_cook_out[strlen(desc_cook_out)-2] = '\0';
      tor_snprintf(buf, sizeof(buf),"%s.onion %s # client: %s\n",
                   s->service_id, desc_cook_out, client->client_name);
    } else {
      memcpy(extended_desc_cookie, client->descriptor_cookie,
             REND_DESC_COOKIE_LEN);
      extended_desc_cookie[REND_DESC_COOKIE_LEN] =
        ((int)s->auth_type - 1) << 4;
      if (base64_encode(desc_cook_out, 3*REND_DESC_COOKIE_LEN_BASE64+1,
                        extended_desc_cookie,
                        REND_DESC_COOKIE_LEN+1) < 0) {
        log_warn(LD_BUG, "Could not base64-encode descriptor cookie.");
        goto err;
      }
      desc_cook_out[strlen(desc_cook_out)-3] = '\0'; /* Remove A= and
                                                        newline. */
      tor_snprintf(buf, sizeof(buf),"%s.onion %s # client: %s\n",
                   service_id, desc_cook_out, client->client_name);
    }

    if (fputs(buf, hfile)<0) {
      log_warn(LD_FS, "Could not append host entry to file: %s",
               strerror(errno));
      goto err;
    }
  } SMARTLIST_FOREACH_END(client);

  finish_writing_to_file(open_cfile);
  finish_writing_to_file(open_hfile);

  goto done;
 err:
  r = -1;
  if (open_cfile)
    abort_writing_to_file(open_cfile);
  if (open_hfile)
    abort_writing_to_file(open_hfile);
 done:
  if (client_keys_str) {
    tor_strclear(client_keys_str);
    tor_free(client_keys_str);
  }
  strmap_free(parsed_clients, rend_authorized_client_strmap_item_free);

  memwipe(cfname, 0, sizeof(cfname));

  /* Clear stack buffers that held key-derived material. */
  memwipe(buf, 0, sizeof(buf));
  memwipe(desc_cook_out, 0, sizeof(desc_cook_out));
  memwipe(service_id, 0, sizeof(service_id));
  memwipe(extended_desc_cookie, 0, sizeof(extended_desc_cookie));

  return r;
}

/** Return the service whose public key has a digest of <b>digest</b>, or
 * NULL if no such service exists.
 */
static rend_service_t *
rend_service_get_by_pk_digest(const char* digest)
{
  SMARTLIST_FOREACH(rend_service_list, rend_service_t*, s,
                    if (tor_memeq(s->pk_digest,digest,DIGEST_LEN))
                        return s);
  return NULL;
}

/** Return 1 if any virtual port in <b>service</b> wants a circuit
 * to have good uptime. Else return 0.
 */
static int
rend_service_requires_uptime(rend_service_t *service)
{
  int i;
  rend_service_port_config_t *p;

  for (i=0; i < smartlist_len(service->ports); ++i) {
    p = smartlist_get(service->ports, i);
    if (smartlist_contains_int_as_string(get_options()->LongLivedPorts,
                                  p->virtual_port))
      return 1;
  }
  return 0;
}

/** Check client authorization of a given <b>descriptor_cookie</b> for
 * <b>service</b>. Return 1 for success and 0 for failure. */
static int
rend_check_authorization(rend_service_t *service,
                         const char *descriptor_cookie)
{
  rend_authorized_client_t *auth_client = NULL;
  tor_assert(service);
  tor_assert(descriptor_cookie);
  if (!service->clients) {
    log_warn(LD_BUG, "Can't check authorization for a service that has no "
                     "authorized clients configured.");
    return 0;
  }

  /* Look up client authorization by descriptor cookie. */
  SMARTLIST_FOREACH(service->clients, rend_authorized_client_t *, client, {
    if (tor_memeq(client->descriptor_cookie, descriptor_cookie,
                REND_DESC_COOKIE_LEN)) {
      auth_client = client;
      break;
    }
  });
  if (!auth_client) {
    char descriptor_cookie_base64[3*REND_DESC_COOKIE_LEN_BASE64];
    base64_encode(descriptor_cookie_base64, sizeof(descriptor_cookie_base64),
                  descriptor_cookie, REND_DESC_COOKIE_LEN);
    log_info(LD_REND, "No authorization found for descriptor cookie '%s'! "
                      "Dropping cell!",
             descriptor_cookie_base64);
    return 0;
  }

  /* Allow the request. */
  log_debug(LD_REND, "Client %s authorized for service %s.",
            auth_client->client_name, service->service_id);
  return 1;
}

/** Called when <b>intro</b> will soon be removed from
 * <b>service</b>'s list of intro points. */
static void
rend_service_note_removing_intro_point(rend_service_t *service,
                                       rend_intro_point_t *intro)
{
  time_t now = time(NULL);

  /* Don't process an intro point twice here. */
  if (intro->rend_service_note_removing_intro_point_called) {
    return;
  } else {
    intro->rend_service_note_removing_intro_point_called = 1;
  }

  /* Update service->n_intro_points_wanted based on how long intro
   * lasted and how many introductions it handled. */
  if (intro->time_published == -1) {
    /* This intro point was never used.  Don't change
     * n_intro_points_wanted. */
  } else {
    /* We want to increase the number of introduction points service
     * operates if intro was heavily used, or decrease the number of
     * intro points if intro was lightly used.
     *
     * We consider an intro point's target 'usage' to be
     * INTRO_POINT_LIFETIME_INTRODUCTIONS introductions in
     * INTRO_POINT_LIFETIME_MIN_SECONDS seconds.  To calculate intro's
     * fraction of target usage, we divide the fraction of
     * _LIFETIME_INTRODUCTIONS introductions that it has handled by
     * the fraction of _LIFETIME_MIN_SECONDS for which it existed.
     *
     * Then we multiply that fraction of desired usage by a fudge
     * factor of 1.5, to decide how many new introduction points
     * should ideally replace intro (which is now closed or soon to be
     * closed).  In theory, assuming that introduction load is
     * distributed equally across all intro points and ignoring the
     * fact that different intro points are established and closed at
     * different times, that number of intro points should bring all
     * of our intro points exactly to our target usage.
     *
     * Then we clamp that number to a number of intro points we might
     * be willing to replace this intro point with and turn it into an
     * integer. then we clamp it again to the number of new intro
     * points we could establish now, then we adjust
     * service->n_intro_points_wanted and let rend_services_introduce
     * create the new intro points we want (if any).
     */
    const double intro_point_usage =
      intro_point_accepted_intro_count(intro) /
      (double)(now - intro->time_published);
    const double intro_point_target_usage =
      INTRO_POINT_LIFETIME_INTRODUCTIONS /
      (double)INTRO_POINT_LIFETIME_MIN_SECONDS;
    const double fractional_n_intro_points_wanted_to_replace_this_one =
      (1.5 * (intro_point_usage / intro_point_target_usage));
    unsigned int n_intro_points_wanted_to_replace_this_one;
    unsigned int n_intro_points_wanted_now;
    unsigned int n_intro_points_really_wanted_now;
    int n_intro_points_really_replacing_this_one;

    if (fractional_n_intro_points_wanted_to_replace_this_one >
        NUM_INTRO_POINTS_MAX) {
      n_intro_points_wanted_to_replace_this_one = NUM_INTRO_POINTS_MAX;
    } else if (fractional_n_intro_points_wanted_to_replace_this_one < 0) {
      n_intro_points_wanted_to_replace_this_one = 0;
    } else {
      n_intro_points_wanted_to_replace_this_one = (unsigned)
        fractional_n_intro_points_wanted_to_replace_this_one;
    }

    n_intro_points_wanted_now =
      service->n_intro_points_wanted +
      n_intro_points_wanted_to_replace_this_one - 1;

    if (n_intro_points_wanted_now < NUM_INTRO_POINTS_DEFAULT) {
      /* XXXX This should be NUM_INTRO_POINTS_MIN instead.  Perhaps
       * another use of NUM_INTRO_POINTS_DEFAULT should be, too. */
      n_intro_points_really_wanted_now = NUM_INTRO_POINTS_DEFAULT;
    } else if (n_intro_points_wanted_now > NUM_INTRO_POINTS_MAX) {
      n_intro_points_really_wanted_now = NUM_INTRO_POINTS_MAX;
    } else {
      n_intro_points_really_wanted_now = n_intro_points_wanted_now;
    }

    n_intro_points_really_replacing_this_one =
      n_intro_points_really_wanted_now - service->n_intro_points_wanted + 1;

    log_info(LD_REND, "Replacing closing intro point for service %s "
             "with %d new intro points (wanted %g replacements); "
 