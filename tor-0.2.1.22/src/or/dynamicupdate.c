/*
 * Copyright © 2010 Edward Smith
 *
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution. 
 *
 * 3. The names of the contributors may not be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE. 
 *
 */

/**
   Functions and state related to Dynamic Software updating.
 */

#include <kitsune.h>
#include "dsu.h"
#include "or.h"

#define V0 "/home/tedks/Projects/plum/workdir/examples/tor/tor-0.2.1.18/src/or/tor-update.so"
#define V1 "/home/tedks/Projects/plum/workdir/examples/tor/tor-0.2.1.19/src/or/tor-update.so"

static char * next_version = V0;

void migrate_dns_conn(connection_t *conn);
void migrate_or_conn(connection_t *conn);

/** Set the update predicate to true. This will cause us to update on the next
    call to kitsune_update.
 */
void
signal_update(void) 
{
  struct timeval tv = { 0, 0 };
  char   upd_path_fname[20];
  FILE * upd_path_fp;
  
  log(LOG_NOTICE, LD_GENERAL, "Initiating dynamic update.");

  if (get_options()->DSUTarget != NULL)
    next_version = get_options()->DSUTarget;

  /* force an update */
  kitsune_signal_update();

  /* write out the update path */
  snprintf(upd_path_fname, 20, "/tmp/%d.upd", getpid());
  upd_path_fp = fopen(upd_path_fname, "w");
  assert(upd_path_fp);
  fputs(next_version, upd_path_fp);
  fclose(upd_path_fp);
  
  /* signal the main loop to exit if it wouldn't have */
  event_loopexit(&tv);
}

void
migrate_connection_smartlist(smartlist_t *connection_list)
{
  int was_reading, was_writing;
  void * conn_read_callback = 
    kitsune_lookup_key_new("main.c/conn_read_callback");
  void * conn_write_callback = 
    kitsune_lookup_key_new("main.c/conn_write_callback");
  
  SMARTLIST_FOREACH(connection_list, connection_t *, conn, 
                    {
                      was_reading = was_writing = 0;
                      log_debug(LD_DSU, "Migrating event for fd %d, type %s",
                                conn->s, conn_type_to_string(conn->type));

                      conn->read_event->ev_callback = conn_read_callback;
                      conn->write_event->ev_callback = conn_write_callback;
                      migrate_dns_conn(conn);
                      migrate_or_conn(conn);
                    });
}

void
migrate_or_conn(connection_t * conn)
{
  if (conn->magic != OR_CONNECTION_MAGIC)
    return;

  or_connection_t *or_conn = TO_OR_CONN(conn);
  void * always_accept_verify_cb = 
    kitsune_lookup_key_new("tortls.c/always_accept_verify_cb");
  if (or_conn->tls == NULL)
    return;
  /* we need to reset the SSL callback */
  SSL_set_verify(or_conn->tls->ssl, SSL_VERIFY_PEER, 
                 always_accept_verify_cb);
  if (or_conn->tls->negotiated_callback)\
    tor_tls_set_renegotiate_callback(or_conn->tls,
                                     kitsune_lookup_key_new("connection_or.c/connection_or_tls_renegotiated_cb"),
                                     or_conn);
}

#define XFORM_CONN_LIST(list)                               \
  int STATIC_XFORM(main_c, list)(void *_new_array)          \
  {                                                         \
    smartlist_t ** new_array = (smartlist_t **)_new_array;  \
    smartlist_t ** old_array =                              \
      kitsune_lookup_key_old("main.c/"#list);                \
                                                            \
    if (old_array == NULL)                                  \
      return 1;                                             \
    memcpy(new_array, old_array, sizeof(old_array));        \
    migrate_connection_smartlist(*new_array);               \
    return 1;                                               \
  }

XFORM_CONN_LIST(connection_array)
XFORM_CONN_LIST(active_linked_connection_lst)
XFORM_CONN_LIST(closeable_connection_lst)

int
STATIC_XFORM(log_c, logfiles)(void *_new_logfiles)
{
  logfile_t ** new_logfiles = (logfile_t **)_new_logfiles;
  logfile_t ** old_logfiles = kitsune_lookup_key_old("log.c/logfiles");
  logfile_t * iter;
  extern void control_event_logmsg(int, uint32_t, const char *);
  
  /* Copy over the old pointer into the heap */
  memcpy(new_logfiles, old_logfiles, sizeof(logfile_t *));
  /* iterate over the list and update the pointers */
  for(iter = (*new_logfiles); iter != NULL; iter = iter->next) {
    if (iter->callback)
      iter->callback = control_event_logmsg;
  }
  return 1;  
}

int
LOCAL_STATIC_XFORM(main_c, handle_signals, signal_events)
     (void *_new_signal_events)
{
  int i;
  struct event ** new_signal_events = (struct event **)_new_signal_events;
  struct event ** old_signal_events = 
    kitsune_lookup_key_old("main.c/handle_signals#signal_events");
  int * signals = kitsune_lookup_key_old("main.c/handle_signals#signals");
  void * signal_callback = kitsune_lookup_key_new("main.c/signal_callback");
  
  memcpy(new_signal_events, old_signal_events, sizeof(struct event *));
  
  for (i = 0; signals[i] >= 0 ; i++) {
    log_debug(LD_DSU, "Old signal_callback is %p, writing %p's callback to %p",
              ((*old_signal_events)[i]).ev_callback, &((*new_signal_events)[i]),
              signal_callback);
    ((*new_signal_events)[i]).ev_callback = signal_callback;
  }
  return 1;
}

int
LOCAL_STATIC_XFORM(dns_c, dns_launch_correctness_checks, launch_event)
     (void *_new_launch_event)
{
  struct event ** new_launch_event = (struct event **)_new_launch_event;
  struct event ** old_launch_event = 
    kitsune_lookup_key_old("dns.c/dns_launch_correctness_checks#launch_event");
  void * launch_test_addresses = 
    kitsune_lookup_key_new("dns.c/launch_test_addresses");

  memcpy(new_launch_event, old_launch_event, sizeof(struct event *));
  if (*new_launch_event)
    (*new_launch_event)->ev_callback = launch_test_addresses;
  return 1;
}

int
STATIC_XFORM(main_c, timeout_event)(void *_new_timeout_event)
{
  struct event ** new_timeout_event = (struct event **)_new_timeout_event;
  struct event ** old_timeout_event = (struct event **)
    kitsune_lookup_key_old("main.c/timeout_event");
  void * second_elapsed_callback = 
    kitsune_lookup_key_new("main.c/second_elapsed_callback");
  
  memcpy(new_timeout_event, old_timeout_event, sizeof(struct event *));
  if (*new_timeout_event)
    (*new_timeout_event)->ev_callback = second_elapsed_callback;
  return 1;
}

int
STATIC_XFORM(tortls_c, global_tls_context)(void *_new_global_tls_context)
{
  tor_tls_context_t **new_global_tls_context = 
    (tor_tls_context_t **)_new_global_tls_context;
  tor_tls_context_t ** old_global_tls_context =
    kitsune_lookup_key_old("tortls.c/global_tls_context");
  void * always_accept_verify_cb = 
    kitsune_lookup_key_new("tortls.c/always_accept_verify_cb");
  
  memcpy(new_global_tls_context, old_global_tls_context, 
         sizeof(tor_tls_context_t *));

  /* we need to reset the callback */
  SSL_CTX_set_verify((*new_global_tls_context)->ctx, SSL_VERIFY_PEER,
                     always_accept_verify_cb);
  return 1;
}

int
STATIC_XFORM(eventdns_c, server_head)(void *_new_server_head)
{
  struct nameserver **new_server_head = (struct nameserver **)_new_server_head;
  struct nameserver **old_server_head = 
    kitsune_lookup_key_old("eventdns.c/server_head");
  struct nameserver * first, *iter;
  void * nameserver_prod_callback = 
    kitsune_lookup_key_new("eventdns.c/nameserver_prod_callback");
  void * nameserver_ready_callback =
    kitsune_lookup_key_new("eventdns.c/nameserver_ready_callback");
  
  memcpy(new_server_head, old_server_head, sizeof(struct nameserver *));

  /* unroll the first transformation so that we can go through the loop */
  if ((first = *new_server_head) != NULL) {
    first->event.ev_callback = nameserver_ready_callback;
    
    for(iter = first->next; iter != first; iter = iter->next) {
      iter->event.ev_callback = nameserver_ready_callback;
      iter->timeout_event.ev_callback = nameserver_prod_callback;
    }
  }
  return 1;
}

void
migrate_evdns_request_user_callback(struct evdns_request *req)
{
  char *old_key;
  void *new_fun;

  /* blithley assign the new function; don't bother checking for null */
  old_key = kitsune_lookup_addr_old(req->user_callback);
  new_fun = kitsune_lookup_key_new(old_key);
  req->user_callback = new_fun;
}

#define XFORM_REQ_LIST(list)                                            \
  int                                                                   \
  STATIC_XFORM(eventdns_c, list)(void *_new_list)                       \
  {                                                                     \
    struct evdns_request ** new_list =                                  \
      (struct evdns_request **)_new_list;                               \
    struct evdns_request ** old_list =                                  \
      kitsune_lookup_key_old("eventdns.c/"#list);                        \
    struct evdns_request *iter;                                         \
    evdns_callback_type  evdns_request_timeout_callback =               \
      kitsune_lookup_key_new("eventdns.c/evdns_request_timeout_callback"); \
                                                                        \
    memcpy(new_list, old_list, sizeof(struct evdns_request *));         \
    if (*new_list == NULL)                                              \
      return 1;                                                         \
                                                                        \
    (*new_list)->timeout_event.ev_callback =                            \
      evdns_request_timeout_callback;                                   \
    migrate_evdns_request_user_callback(*new_list);                     \
                                                                        \
    for (iter = (*new_list)->next; iter != *new_list;                   \
         iter = iter->next) {                                           \
      iter->timeout_event.ev_callback = evdns_request_timeout_callback; \
      migrate_evdns_request_user_callback(iter);                        \
    }                                                                   \
    return 1;                                                           \
  }                                                                     

XFORM_REQ_LIST(req_head)
XFORM_REQ_LIST(req_waiting_head)

void 
migrate_dns_conn(connection_t *conn)
{
  if (!conn->dns_server_port)
    return;
  void * server_port_ready_callback = 
    kitsune_lookup_key_new("eventdns.c/server_port_ready_callback");
  
  struct evdns_server_port *sp = conn->dns_server_port;
  sp->event.ev_callback = server_port_ready_callback;
}
