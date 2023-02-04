/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "geoip.h"
#include "nodelist.h"
#include "policies.h"
#include "router.h"
#include "routerparse.h"
#include "routerset.h"

/** A routerset specifies constraints on a set of possible routerinfos, based
 * on their names, identities, or addresses.  It is optimized for determining
 * whether a router is a member or not, in O(1+P) time, where P is the number
 * of address policy constraints. */
struct routerset_t {
  /** A list of strings for the elements of the policy.  Each string is either
   * a nickname, a hexadecimal identity fingerprint, or an address policy.  A
   * router belongs to the set if its nickname OR its identity OR its address
   * matches an entry here. */
  smartlist_t *list;
  /** A map from lowercase nicknames of routers in the set to (void*)1 */
  strmap_t *names;
  /** A map from identity digests routers in the set to (void*)1 */
  digestmap_t *digests;
  /** An address policy for routers in the set.  For implementation reasons,
   * a router belongs to the set if it is _rejected_ by this policy. */
  smartlist_t *policies;

  /** A human-readable description of what this routerset is for.  Used in
   * log messages. */
  char *description;

  /** A list of the country codes in this set. */
  smartlist_t *country_names;
  /** Total number of countries we knew about when we built <b>countries</b>.*/
  int n_countries;
  /** Bit array mapping the return value of geoip_get_country() to 1 iff the
   * country is a member of this routerset.  Note that we MUST call
   * routerset_refresh_countries() whenever the geoip country list is
   * reloaded. */
  bitarray_t *countries;
};

/** Return a new empty routerset. */
routerset_t *
routerset_new(void)
{
  routerset_t *result = tor_malloc_zero(sizeof(routerset_t));
  result->list = smartlist_new();
  result->names = strmap_new();
  result->digests = digestmap_new();
  result->policies = smartlist_new();
  result->country_names = smartlist_new();
  return result;
}

/** If <b>c</b> is a country code in the form {cc}, return a newly allocated
 * string holding the "cc" part.  Else, return NULL. */
static char *
routerset_get_countryname(const char *c)
{
  char *country;

  if (strlen(c) < 4 || c[0] !='{' || c[3] !='}')
    return NULL;

  country = tor_strndup(c+1, 2);
  tor_strlower(country);
  return country;
}

/** Update the routerset's <b>countries</b> bitarray_t. Called whenever
 * the GeoIP IPv4 database is reloaded.
 */
void
routerset_refresh_countries(routerset_t *target)
{
  int cc;
  bitarray_free(target->countries);

  if (!geoip_is_loaded(AF_INET)) {
    target->countries = NULL;
    target->n_countries = 0;
    return;
  }
  target->n_countries = geoip_get_n_countries();
  target->countries = bitarray_init_zero(target->n_countries);
  SMARTLIST_FOREACH_BEGIN(target->country_names, const char *, country) {
    cc = geoip_get_country(country);
    if (cc >= 0) {
      tor_assert(cc < target->n_countries);
      bitarray_set(target->countries, cc);
    } else {
      log_warn(LD_CONFIG, "Country code '%s' is not recognized.",
          country);
    }
  } SMARTLIST_FOREACH_END(country);
}

/** Parse the string <b>s</b> to create a set of routerset entries, and add
 * them to <b>target</b>.  In log messages, refer to the string as
 * <b>description</b>.  Return 0 on success, -1 on failure.
 *
 * Three kinds of elements are allowed in routersets: nicknames, IP address
 * patterns, and fingerprints.  They may be surrounded by optional space, and
 * must be separated by commas.
 */
int
routerset_parse(routerset_t *target, const char *s, const char *description)
{
  int r = 0;
  int added_countries = 0;
  char *countryname;
  smartlist_t *list = smartlist_new();
  smartlist_split_string(list, s, ",",
                         SPLIT_SKIP_SPACE | SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH_BEGIN(list, char *, nick) {
      addr_policy_t *p;
      if (is_legal_hexdigest(nick)) {
        char d[DIGEST_LEN];
        if (*nick == '$')
          ++nick;
        log_debug(LD_CONFIG, "Adding identity %s to %s", nick, description);
        base16_decode(d, sizeof(d), nick, HEX_DIGEST_LEN);
        digestmap_set(target->digests, d, (void*)1);
      } else if (is_legal_nickname(nick)) {
        log_debug(LD_CONFIG, "Adding nickname %s to %s", nick, description);
        strmap_set_lc(target->names, nick, (void*)1);
      } else if ((countryname = routerset_get_countryname(nick)) != NULL) {
        log_debug(LD_CONFIG, "Adding country %s to %s", nick,
                  description);
        smartlist_add(target->country_names, countryname);
        added_countries = 1;
      } else if ((strchr(nick,'.') || strchr(n