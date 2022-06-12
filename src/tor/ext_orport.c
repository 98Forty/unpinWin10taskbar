
/* Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file ext_orport.c
 * \brief Code implementing the Extended ORPort.
*/

#define EXT_ORPORT_PRIVATE
#include "or.h"
#include "connection.h"
#include "connection_or.h"
#include "ext_orport.h"
#include "control.h"
#include "config.h"
#include "tor_util.h"
#include "onion_main.h"

/** Allocate and return a structure capable of holding an Extended
 *  ORPort message of body length <b>len</b>. */
ext_or_cmd_t *
ext_or_cmd_new(uint16_t len)
{
  size_t size = STRUCT_OFFSET(ext_or_cmd_t, body) + len;
  ext_or_cmd_t *cmd = tor_malloc(size);
  cmd->len = len;
  return cmd;
}

/** Deallocate the Extended ORPort message in <b>cmd</b>. */
void
ext_or_cmd_free(ext_or_cmd_t *cmd)
{
  tor_free(cmd);
}

/** Get an Extended ORPort message from <b>conn</b>, and place it in
 *  <b>out</b>. Return -1 on fail, 0 if we need more data, and 1 if we
 *  successfully extracted an Extended ORPort command from the
 *  buffer.  */
static int
connection_fetch_ext_or_cmd_from_buf(connection_t *conn, ext_or_cmd_t **out)
{
  IF_HAS_BUFFEREVENT(conn, {
    struct evbuffer *input = bufferevent_get_input(conn->bufev);
    return fetch_ext_or_command_from_evbuffer(input, out);
  }) ELSE_IF_NO_BUFFEREVENT {
    return fetch_ext_or_command_from_buf(conn->inbuf, out);
  }
}

/** Write an Extended ORPort message to <b>conn</b>. Use
 *  <b>command</b> as the command type, <b>bodylen</b> as the body
 *  length, and <b>body</b>, if it's present, as the body of the
 *  message. */
STATIC int
connection_write_ext_or_command(connection_t *conn,
                                uint16_t command,
                                const char *body,
                                size_t bodylen)
{
  char header[4];
  if (bodylen > UINT16_MAX)
    return -1;
  set_uint16(header, htons(command));
  set_uint16(header+2, htons(bodylen));
  connection_write_to_buf(header, 4, conn);
  if (bodylen) {
    tor_assert(body);
    connection_write_to_buf(body, bodylen, conn);
  }
  return 0;