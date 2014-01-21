/*
** dsu.h
** 
** Made by Teddy Smith
** Login   <tedks@anglachel>
** 
**
*/

#ifndef   	DSU_H_
# define   	DSU_H_
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/err.h>
#include <openssl/tls1.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>

#include <sys/queue.h>

#include "or.h"
#include "ht.h"
#include "eventdns.h"

#define u64 uint64_t
#define u32 uint32_t
#define u16 uint16_t
#define u8	uint8_t

typedef struct logfile_t {
  struct logfile_t *next; /**< Next logfile_t in the linked list. */
  char *filename; /**< Filename to open. */
  int fd; /**< fd to receive log messages, or -1 for none. */
  int seems_dead; /**< Boolean: true if the stream seems to be kaput. */
  int needs_close; /**< Boolean: true if the stream gets closed on shutdown. */
  int is_temporary; /**< Boolean: close after initializing logging subsystem.*/
  int is_syslog; /**< Boolean: send messages to syslog. */
  log_callback callback; /**< If not NULL, send messages to this function. */
  log_severity_list_t *severities; /**< Which severity of messages should we
                                    * log for each log domain? */
} logfile_t;

/* from tortls.c */
typedef struct tor_tls_context_t {
  int refcnt;
  SSL_CTX *ctx;
  X509 *my_cert;
  X509 *my_id_cert;
  crypto_pk_env_t *key;
} tor_tls_context_t;

struct tor_tls_t {
  HT_ENTRY(tor_tls_t) node;
  tor_tls_context_t *context; /** A link to the context object for this tls. */
  SSL *ssl; /**< An OpenSSL SSL object. */
  int socket; /**< The underlying file descriptor for this TLS connection. */
  char *address; /**< An address to log when describing this connection. */
  enum {
    TOR_TLS_ST_HANDSHAKE, TOR_TLS_ST_OPEN, TOR_TLS_ST_GOTCLOSE,
    TOR_TLS_ST_SENTCLOSE, TOR_TLS_ST_CLOSED, TOR_TLS_ST_RENEGOTIATE,
  } state : 3; /**< The current SSL state, depending on which operations have
                * completed successfully. */
  unsigned int isServer:1; /**< True iff this is a server-side connection */
  unsigned int wasV2Handshake:1; /**< True iff the original handshake for
                                  * this connection used the updated version
                                  * of the connection protocol (client sends
                                  * different cipher list, server sends only
                                  * one certificate). */
 /** True iff we should call negotiated_callback when we're done reading. */
  unsigned int got_renegotiate:1;
  size_t wantwrite_n; /**< 0 normally, >0 if we returned wantwrite last
                       * time. */
  /** Last values retrieved from BIO_number_read()/write(); see
   * tor_tls_get_n_raw_bytes() for usage.
   */
  unsigned long last_write_count;
  unsigned long last_read_count;
  /** If set, a callback to invoke whenever the client tries to renegotiate
   * the handshake. */
  void (*negotiated_callback)(tor_tls_t *tls, void *arg);
  /** Argument to pass to negotiated_callback. */
  void *callback_arg;
};


struct evdns_request {
	u8 *request; /* the dns packet data */
	unsigned int request_len;
	int reissue_count;
	int tx_count;  /* the number of times that this packet has been sent */
	unsigned int request_type; /* TYPE_PTR or TYPE_A */
	void *user_pointer;	 /* the pointer given to us for this request */
	evdns_callback_type user_callback;
	struct nameserver *ns;	/* the server which we last sent it */

	/* elements used by the searching code */
	int search_index;
	struct search_state *search_state;
	char *search_origname;	/* needs to be mm_free()ed */
	int search_flags;

	/* these objects are kept in a circular list */
	struct evdns_request *next, *prev;

	u16 timeout_event_deleted; /**< Debugging: where was timeout_event
								* deleted?  0 for "it's added." */
	struct event timeout_event;

	u16 trans_id;  /* the transaction id */
	char request_appended;	/* true if the request pointer is data which follows this struct */
	char transmit_me;  /* needs to be transmitted */
};

/* Represents a local port where we're listening for DNS requests. Right now, */
/* only UDP is supported. */
struct evdns_server_port {
	int socket; /* socket we use to read queries and write replies. */
	int refcnt; /* reference count. */
	char choked; /* Are we currently blocked from writing? */
	char closing; /* Are we trying to close this port, pending writes? */
	evdns_request_callback_fn_type user_callback; /* Fn to handle requests */
	void *user_data; /* Opaque pointer passed to user_callback */
	struct event event; /* Read/write event */
	/* circular list of replies that we want to write. */
	struct server_request *pending_replies;
};

/* Represents a request that we've received as a DNS server, and holds */
/* the components of the reply as we're constructing it. */
struct server_request {
	/* Pointers to the next and previous entries on the list of replies */
	/* that we're waiting to write.	 Only set if we have tried to respond */
	/* and gotten EAGAIN. */
	struct server_request *next_pending;
	struct server_request *prev_pending;

	u16 trans_id; /* Transaction id. */
	struct evdns_server_port *port; /* Which port received this request on? */
	struct sockaddr_storage addr; /* Where to send the response */
	socklen_t addrlen; /* length of addr */

	int n_answer; /* how many answer RRs have been set? */
	int n_authority; /* how many authority RRs have been set? */
	int n_additional; /* how many additional RRs have been set? */

	struct server_reply_item *answer; /* linked list of answer RRs */
	struct server_reply_item *authority; /* linked list of authority RRs */
	struct server_reply_item *additional; /* linked list of additional RRs */

	/* Constructed response.  Only set once we're ready to send a reply. */
	/* Once this is set, the RR fields are cleared, and no more should be set. */
	char *response;
	size_t response_len;

	/* Caller-visible fields: flags, questions. */
	struct evdns_server_request base;
};

struct nameserver {
	int socket;	 /* a connected UDP socket */
	struct sockaddr_storage address;
	int failed_times;  /* number of times which we have given this server a chance */
	int timedout;  /* number of times in a row a request has timed out */
	struct event event;
	/* these objects are kept in a circular list */
	struct nameserver *next, *prev;
	u16 timeout_event_deleted; /**< Debugging: where was timeout_event
								* deleted?  0 for "it's added." */
	struct event timeout_event; /* used to keep the timeout for */
								/* when we next probe this server. */
								/* Valid if state == 0 */
	char state;	 /* zero if we think that this server is down */
	char choked;  /* true if we have an EAGAIN from this server's socket */
	char write_waiting;	 /* true if we are waiting for EV_WRITE events */
};

/* helper macro */
#define OFFSET_OF(st, member) ((off_t) (((char*)&((st*)0)->member)-(char*)0))

/* Given a pointer to an evdns_server_request, get the corresponding */
/* server_request. */
#define TO_SERVER_REQUEST(base_ptr)										\
	((struct server_request*)											\
	 (((char*)(base_ptr) - OFFSET_OF(struct server_request, base))))

void signal_update(void) ;

#endif 	    /* !DSU_H_ */
