/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "confparse.h"
#include "routerset.h"

static uint64_t config_parse_memunit(const char *s, int *ok);
static int config_parse_msec_interval(const char *s, int *ok);
static int config_parse_interval(const char *s, int *ok);
static void config_reset(const config_format_t *fmt, void *options,
                         const config_var_t *var, int use_defaults);

/** Allocate an empty configuration object of a given format type. */
void *
config_new(const config_format_t *fmt)
{
  void *opts = tor_malloc_zero(fmt->size);
  *(uint32_t*)STRUCT_VAR_P(opts, fmt->magic_offset) = fmt->magic;
  CONFIG_CHECK(fmt, opts);
  return opts;
}

/*
 * Functions to parse config options
 */

/** If <b>option</b> is an official abbreviation for a longer option,
 * return the longer option.  Otherwise return <b>option</b>.
 * If <b>command_line</b> is set, apply all abbreviations.  Otherwise, only
 * apply abbreviations that work for the config file and the command line.
 * If <b>warn_obsolete</b> is set, warn about deprecated names. */
const char *
config_expand_abbrev(const config_format_t *fmt, const char *option,
                     int command_line, int warn_obsolete)
{
  int i;
  if (! fmt->abbrevs)
    return option;
  for (i=0; fmt->abbrevs[i].abbreviated; ++i) {
    /* Abbreviations are case insensitive. */
    if (!strcasecmp(option,fmt->abbrevs[i].abbreviated) &&
        (command_line || !fmt->abbrevs[i].commandline_only)) {
      if (warn_obsolete && fmt->abbrevs[i].warn) {
        log_warn(LD_CONFIG,
                 "The configuration option '%s' is deprecated; "
                 "use '%s' instead.",
                 fmt->abbrevs[i].abbreviated,
                 fmt->abbrevs[i].full);
      }
      /* Keep going through the list in case we want to rewrite it more.
       * (We could imagine recursing here, but I don't want to get the
       * user into an infinite loop if we craft our list wrong.) */
      option = fmt->abbrevs[i].full;
    }
  }
  return option;
}

/** Helper: allocate a new configuration option mapping 'key' to 'val',
 * append it to *<b>lst</b>. */
void
config_line_append(config_line_t **lst,
                   const char *key,
                   const char *val)
{
  config_line_t *newline;

  newline = tor_malloc_zero(sizeof(config_line_t));
  newline->key = tor_strdup(key);
  newline->value = tor_strdup(val);
  newline->next = NULL;
  while (*lst)
    lst = &((*lst)->next);

  (*lst) = newline;
}

/** Return the line in <b>lines</b> whose key is exactly <b>key</b>, or NULL
 * if no such key exists. For handling commandline-only options only; other
 * options should be looked up in the appropriate data structure. */
const config_line_t *
config_line_find(const config_line_t *lines,
                 const char *key)
{
  const config_line_t *cl;
  for (cl = lines; cl; cl = cl->next) {
    if (!strcmp(cl->key, key))
      return cl;
  }
  return NULL;
}

/** Helper: parse the config string and strdup into key/value
 * strings. Set *result to the list, or NULL if parsing the string
 * failed.  Return 0 on success, -1 on failure. Warn and ignore any
 * misformatted lines.
 *
 * If <b>extended</b> is set, then treat keys beginning with / and with + as
 * indicating "clear" and "append" respectively. */
int
config_get_lines(const char *string, config_line_t **result, int extended)
{
  config_line_t *list = NULL, **next;
  char *k, *v;
  const char *parse_err;

  next = &list;
  do {
    k = v = NULL;
    string = parse_config_line_from_str_verbose(string, &k, &v, &parse_err);
    if (!string) {
      log_warn(LD_CONFIG, "Error while parsing configuration: %s",
               parse_err?parse_err:"<unknown>");
      config_free_lines(list);
      tor_free(k);
      tor_free(v);
      return -1;
    }
    if (k && v) {
      unsigned command = CONFIG_LINE_NORMAL;
      if (extended) {
        if (k[0] == '+') {
          char *k_new = tor_strdup(k+1);
          tor_free(k);
          k = k_new;
          command = CONFIG_LINE_APPEND;
        } else if (k[0] == '/') {
          char *k_new = tor_strdup(k+1);
          tor_free(k);
          k = k_new;
          tor_free(v);
          v = tor_strdup("");
          command = CONFIG_LINE_CLEAR;
        }
      }
      /* This list can get long, so we keep a pointer to the end of it
       * rather than using config_line_append over and over and getting
       * n^2 performance. */
      *next = tor_malloc_zero(sizeof(config_line_t));
      (*next)->key = k;
      (*next)->value = v;
      (*next)->next = NULL;
      (*next)->command = command;
      next = &((*next)->next);
    } else {
      tor_free(k);
      tor_free(v);
    }
  } while (*string);

  *result = list;
  return 0;
}

/**
 * Free all the configuration lines on the linked list <b>front</b>.
 */
void
config_free_lines(config_line_t *front)
{
  config_line_t *tmp;

  while (front) {
    tmp = front;
    front = tmp->next;

    tor_free(tmp->key);
    tor_free(tmp->value);
    tor_free(tmp);
  }
}

/** As config_find_option, but return a non-const pointer. */
config_var_t *
config_find_option_mutable(config_format_t *fmt, const char *key)
{
  int i;
  size_t keylen = strlen(key);
  if (!keylen)
    return NULL; /* if they say "--" on the command line, it's not an option */
  /* First, check for an exact (case-insensitive) match */
  for (i=0; fmt->vars[i].name; ++i) {
    if (!strcasecmp(key, fmt->vars[i].name)) {
      return &fmt->vars[i];
    }
  }
  /* If none, check for an abbreviated match */
  for (i=0; fmt->vars[i].name; ++i) {
    if (!strncasecmp(key, fmt->vars[i].name, keylen)) {
      log_warn(LD_CONFIG, "The abbreviation '%s' is deprecated. "
               "Please use '%s' instead",
               key, fmt->vars[i].name);
      return &fmt->vars[i];
    }
  }
  /* Okay, unrecognized option */
  return NULL;
}

/** If <b>key</b> is a configuration option, return the corresponding const
 * config_var_t.  Otherwise, if <b>key</b> is a non-standard abbreviation,
 * warn, and return the corresponding const config_var_t.  Otherwise return
 * NULL.
 */
const config_var_t *
config_find_option(const config_format_t *fmt, const char *key)
{
  return config_find_option_mutable((config_format_t*)fmt, key);
}

/** Return the number of option entries in <b>fmt</b>. */
static int
config_count_options(const config_format_t *fmt)
{
  int i;
  for (i=0; fmt->vars[i].name; ++i)
    ;
  return i;
}

/*
 * Functions to assign config options.
 */

/** <b>c</b>-\>key is known to be a real key. Update <b>options</b>
 * with <b>c</b>-\>value and return 0, or return -1 if bad value.
 *
 * Called from config_assign_line() and option_reset().
 */
static int
config_assign_value(const config_format_t *fmt, void *options,
                    config_line_t *c, char **msg)
{
  int i, ok;
  const config_var_t *var;
  void *lvalue;
  int *csv_int;
  smartlist_t *csv_str;

  CONFIG_CHECK(fmt, options);

  var = config_find_option(fmt, c->key);
  tor_assert(var);

  lvalue = STRUCT_VAR_P(options, var->var_offset);

  switch (var->type) {

  case CONFIG_TYPE_PORT:
    if (!strcasecmp(c->value, "auto")) {
      *(int *)lvalue = CFG_AUTO_PORT;
      break;
    }
    /* fall through */
  case CONFIG_TYPE_INT:
  case CONFIG_TYPE_UINT:
    i = (int)tor_parse_long(c->value, 10,
                            var->type==CONFIG_TYPE_INT ? INT_MIN : 0,
                            var->type==CONFIG_TYPE_PORT ? 65535 : INT_MAX,
                            &ok, NULL);
    if (!ok) {
      tor_asprintf(msg,
          "Int keyword '%s %s' is malformed or out of bounds.",
          c->key, c->value);
      return -1;
    }
    *(int *)lvalue = i;
    break;

  case CONFIG_TYPE_INTERVAL: {
    i = config_parse_interval(c->value, &ok);
    if (!ok) {
      tor_asprintf(msg,
          "Interval '%s %s' is malformed or out of bounds.",
          c->key, c->value);
      return -1;
    }
    *(int *)lvalue = i;
    break;
  }

  case CONFIG_TYPE_MSEC_INTERVAL: {
    i = config_parse_msec_interval(c->value, &ok);
    if (!ok) {
      tor_asprintf(msg,
          "Msec interval '%s %s' is malformed or out of bounds.",
          c->key, c->value);
      return -1;
    }
    *(int *)lvalue = i;
    break;
  }

  case CONFIG_TYPE_MEMUNIT: {
    uint64_t u64 = config_parse_memunit(c->value, &ok);
    if (!ok) {
      tor_asprintf(msg,
          "Value '%s %s' is malformed or out of bounds.",
          c->key, c->value);
      return -1;
    }
    *(uint64_t *)lvalue = u64;
    break;
  }

  case CONFIG_TYPE_BOOL:
    i = (int)tor_parse_long(c->value, 10, 0, 1, &ok, NULL);
    if (!ok) {
      tor_asprintf(msg,
          "Boolean '%s %s' expects 0 or 1.",
          c->key, c->value);
      return -1;
    }
    *(int *)lvalue = i;
    break;

  case CONFIG_TYPE_AUTOBOOL:
    if (!strcmp(c->value, "auto"))
      *(int *)lvalue = -1;
    else if (!strcmp(c->value, "0"))
      *(int *)lvalue = 0;
    else if (!strcmp(c->value, "1"))
      *(int *)lvalue = 1;
    else {
      tor_asprintf(msg, "Boolean '%s %s' expects 0, 1, or 'auto'.",
                   c->key, c->value);
      return -1;
    }
    break;

  case CONFIG_TYPE_STRING:
  case CONFIG_TYPE_FILENAME:
    tor_free(*(char **)lvalue);
    *(char **)lvalue = tor_strdup(c->value);
    break;

  case CONFIG_TYPE_DOUBLE:
    *(double *)lvalue = atof(c->value);
    break;

  case CONFIG_TYPE_ISOTIME:
    if (parse_iso_time(c->value, (time_t *)lvalue)) {
      tor_asprintf(msg,
          "Invalid time '%s' for keyword '%s'", c->value, c->key);
      return -1;
    }
    break;

  case CONFIG_TYPE_ROUTERSET:
    if (*(routerset_t**)lvalue) {
      routerset_free(*(routerset_t**)lvalue);
    }
    *(routerset_t**)lvalue = routerset_new();
    if (routerset_parse(*(routerset_t**)lvalue, c->value, c->key)<0) {
      tor_asprintf(msg, "Invalid exit list '%s' for option '%s'",
                   c->value, c->key);
      return -1;
    }
    break;

  case CONFIG_TYPE_CSV:
    if (*(smartlist_t**)lvalue) {
      SMARTLIST_FOREACH(*(smartlist_t**)lvalue, char *, cp, tor_free(cp));
      smartlist_clear(*(smartlist_t**)lvalue);
    } else {
      *(smartlist_t**)lvalue = smartlist_new();
    }

    smartlist_split_string(*(smartlist_t**)lvalue, c->value, ",",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    break;

  case CONFIG_TYPE_CSV_INTERVAL:
    if (*(smartlist_t**)lvalue) {
      SMARTLIST_FOREACH(*(smartlist_t**)lvalue, int *, cp, tor_free(cp));
      smartlist_clear(*(smartlist_t**)lvalue);
    } else {
      *(smartlist_t**)lvalue = smartlist_new();
    }
    csv_str = smartlist_new();
    smartlist_split_string(csv_str, c->value, ",",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    SMARTLIST_FOREACH_BEGIN(csv_str, char *, str)
      {
        i = config_parse_interval(str, &ok);
        if (!ok) {
          tor_asprintf(msg,
              "Interval in '%s %s' is malformed or out of bounds.",
              c->key, c->value);
          SMARTLIST_FOREACH(csv_str, char *, cp, tor_free(cp));
          smartlist_free(csv_str);
          return -1;
        }
        csv_int = tor_malloc_zero(sizeof(int));
        *csv_int = i;
        smartlist_add(*(smartlist_t**)lvalue, csv_int);
      }
    SMARTLIST_FOREACH_END(str);
    SMARTLIST_FOREACH(csv_str, char *, cp, tor_free(cp));
    smartlist_free(csv_str);
    break;

  case CONFIG_TYPE_LINELIST:
  case CONFIG_TYPE_LINELIST_S:
    {
      config_line_t *lastval = *(config_line_t**)lvalue;
      if (lastval && lastval->fragile) {
        if (c->command != CONFIG_LINE_APPEND) {
          config_free_lines(lastval);
          *(config_line_t**)lvalue = NULL;
        } else {
          lastval->fragile = 0;
        }
      }

      config_line_append((config_line_t**)lvalue, c->key, c->value);
    }
    break;
  case CONFIG_TYPE_OBSOLETE:
    log_warn(LD_CONFIG, "Skipping obsolete configuration option '%s'", c->key);
    break;
  case CONFIG_TYPE_LINELIST_V:
    tor_asprintf(msg,
        "You may not provide a value for virtual option '%s'", c->key);
    return -1;
  default:
    tor_assert(0);
    break;
  }
  return 0;
}

/** Mark every linelist in <b>options</b> "fragile", so that fresh assignments
 * to it will replace old ones. */
static void
config_mark_lists_fragile(const config_format_t *fmt, void *options)
{
  int i;
  tor_assert(fmt);
  tor_assert(options);

  for (i = 0; fmt->vars[i].name; ++i) {
    const config_var_t *var = &fmt->vars[i];
    config_line_t *list;
    if (var->type != CONFIG_TYPE_LINELIST &&
        var->type != CONFIG_TYPE_LINELIST_V)
      continue;

    list = *(config_line_t **)STRUCT_VAR_P(options, var->var_offset);
    if (list)
      list->fragile = 1;
  }
}

/** If <b>c</b> is a syntactically valid configuration line, update
 * <b>options</b> with its value and return 0.  Otherwise return -1 for bad
 * key, -2 for bad value.
 *
 * If <b>clear_first</b> is set, clear the value first. Then if
 * <b>use_defaults</b> is set, set the value to the default.
 *
 * Called from config_assign().
 */
static int
config_assign_line(const config_format_t *fmt, void *options,
                   config_line_t *c, int use_defaults,
                   int clear_first, bitarray_t *options_seen, char **msg)
{
  const config_var_t *var;

  CONFIG_CHECK(fmt, options);

  var = config_find_option(fmt, c->key)