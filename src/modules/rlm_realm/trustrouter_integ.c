#include <trust_router/tid.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/modules.h>
#include "trustrouter_integ.h"
#include <trust_router/tr_dh.h>
#include <freeradius-devel/realms.h>

static TIDC_INSTANCE *global_tidc = NULL;


struct resp_opaque {
  REALM *output_realm;
  TID_RC result;
  char err_msg[1024];
  char *fr_realm_name;
};


int tr_init(void) 
{
  if (NULL == (global_tidc = tidc_create())) {
    DEBUG2( "tr_init: Error creating global TIDC instance.\n");
    return -1;
  }
  if (NULL == (tidc_set_dh(global_tidc, tr_create_dh_params(NULL, 0)))) {
    DEBUG2( "tr_init: Error creating client DH params.\n");
    return 1;
  }
  return 0;
}

static fr_tls_server_conf_t *construct_tls( TIDC_INSTANCE *inst,
					    home_server_t *hs,
					    TID_SRVR_BLK *server)
{
  fr_tls_server_conf_t *tls = talloc_zero( hs, fr_tls_server_conf_t);
  unsigned char *key_buf = NULL;
  ssize_t keylen;
  char *hexbuf = NULL;
  DH *aaa_server_dh;

  if (tls == NULL)
    goto error;
  aaa_server_dh = tid_srvr_get_dh(server);
  keylen = tr_compute_dh_key(&key_buf, aaa_server_dh->pub_key,
			     tidc_get_dh(inst));
  if (keylen <= 0) {
    DEBUG2("DH error");
    goto error;
  }
  hexbuf = talloc_size(tls, keylen*2 + 1);
  if (hexbuf == NULL)
    goto error;
  tr_bin_to_hex(key_buf, keylen, hexbuf,
	     2*keylen + 1);
  tls->psk_password = hexbuf;
  tls->psk_identity = talloc_strdup(tls, tid_srvr_get_key_name(server)->buf);


  tls->cipher_list = talloc_strdup(tls, "PSK");
  tls->fragment_size = 4200;
  tls->ctx = tls_init_ctx(tls, 1);
  if (tls->ctx == NULL)
    goto error;
  memset(key_buf, 0, keylen);
  tr_dh_free(key_buf);
    return tls;
 error:
    if (key_buf) {
      memset(key_buf, 0, keylen);
      tr_dh_free(key_buf);
    }
    if (hexbuf) {
      memset(hexbuf, 0, keylen*2);
      talloc_free(hexbuf);
    }
    if (tls)
      talloc_free(tls);
    return NULL;
}
  
static char *build_pool_name(void *talloc_ctx, TID_RESP *resp)
{
  size_t index, sa_len, sl;
  TID_SRVR_BLK *server;
  char *pool_name = NULL;
  char addr_buf[256];
  const struct sockaddr *sa;
  pool_name = talloc_strdup(talloc_ctx, "hp-");
  tid_resp_servers_foreach(resp, server, index) {
    tid_srvr_get_address(server, &sa, &sa_len);
    if (0 != getnameinfo(sa, sa_len,
			 addr_buf, sizeof(addr_buf)-1,
			 NULL, 0, NI_NUMERICHOST)) {
      DEBUG2("getnameinfo failed");
      return NULL;
    }
    sl = strlen(addr_buf);
    rad_assert(sl+2 <= sizeof addr_buf);
    addr_buf[sl] = '-';
    addr_buf[sl+1] = '\0';
    pool_name = talloc_strdup_append(pool_name, addr_buf);
  }
  return pool_name;
}

static home_server_t *srvr_blk_to_home_server(
					      void *talloc_ctx,
					      TIDC_INSTANCE *inst,
					      TID_SRVR_BLK *blk)
{
  home_server_t *hs = NULL;
  const struct sockaddr *sa = NULL;
  size_t sa_len = 0;
  fr_ipaddr_t home_server_ip;
  uint16_t port;
  
  rad_assert(blk != NULL);
  tid_srvr_get_address(blk, &sa, &sa_len);
  switch(sa->sa_family) {
  case AF_INET: {
    const struct sockaddr_in *sin = (const struct sockaddr_in *) sa;
      home_server_ip.af = AF_INET;
      home_server_ip.scope = 0;
      home_server_ip.ipaddr.ip4addr = sin->sin_addr;
      port = ntohs(sin->sin_port);
      break;
  }
  case AF_INET6: {
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) sa;
    home_server_ip.af = AF_INET6;
    home_server_ip.scope = sin6->sin6_scope_id;
    home_server_ip.ipaddr.ip6addr = sin6->sin6_addr;
    break;
  }
  default:
    DEBUG2("Unknown address family in tid srvr block");
    return NULL;
  }
  
      hs = home_server_find( &home_server_ip, port,
			     IPPROTO_TCP);
      if (hs) {
	DEBUG2("Found existing home_server %s", hs->name);
	replace_tls(hs, construct_tls(inst, hs, blk));
      } else {
	char nametemp[256];
	if (0 != getnameinfo(sa, sa_len,
			     nametemp,
			     sizeof nametemp,
			     NULL, 0,
			     NI_NUMERICHOST)) {
	  DEBUG2("getnameinfo failed");
	  return NULL;
	}
	hs = talloc_zero(talloc_ctx, home_server_t);
	if (!hs) return NULL;
	hs->type = HOME_TYPE_AUTH;
	hs->ipaddr = home_server_ip;
        hs->src_ipaddr.af = home_server_ip.af;
	hs->name = talloc_strdup(hs, nametemp);
	hs->hostname = talloc_strdup(hs, nametemp);
	  hs->port = port;
	hs->proto = IPPROTO_TCP;
	hs->secret = talloc_strdup(hs, "radsec");
	hs->tls = construct_tls(inst, hs, blk);
	hs->response_window.tv_sec = 30;
	if (hs->tls == NULL) goto error;
	if (!realm_home_server_add(hs, NULL, 0)) {
	  DEBUG2("Failed to add home server");
	  goto error;
	}
      }
      return hs;
 error:
      talloc_free(hs);
      return NULL;
}

static home_pool_t *servers_to_pool(TIDC_INSTANCE *inst,
				   TID_RESP *resp)
{
  char *pool_name;
  home_pool_t *pool = NULL;
  size_t num_servers = 0, index;
  TID_SRVR_BLK *server = NULL;
  pool_name = build_pool_name( resp, resp);
  pool = home_pool_byname(pool_name, HOME_TYPE_AUTH);
  if (pool == NULL) {
      num_servers = tid_resp_get_num_servers(resp);
      pool = talloc_zero_size(NULL, sizeof(*pool) + num_servers *sizeof(home_server_t *));
    if (pool == NULL) goto error;
    pool->type = HOME_POOL_CLIENT_PORT_BALANCE;
    pool->server_type = HOME_TYPE_AUTH;
    pool->name = talloc_steal(pool, pool_name);
    if (pool->name == NULL) goto error;
    pool->num_home_servers = num_servers;


    tid_resp_servers_foreach(resp, server, index) {
      home_server_t *hs = srvr_blk_to_home_server(pool, inst, server);
      if (NULL == hs)
	goto error;
      pool->servers[index] = hs;
    }

    if (!realm_pool_add(pool, NULL)) goto error;
  } else {
    /*Since we have fresh keys we might as well refresh them. So, go loop through the servers.  This will only update the TLS; the servers are guaranteed to exist because the pool has already been added.*/
    tid_resp_servers_foreach(resp,  server, index)
      (void) srvr_blk_to_home_server(pool, inst, server);
  }
  return pool;
 error:
  /*If home_pool_byname succeeds we must not get here or we'll throw away someone else's pool*/
  if (pool)
    talloc_free(pool);
  return NULL;
}

static void tr_response_func( TIDC_INSTANCE *inst,
			     UNUSED TID_REQ *req, TID_RESP *resp,
			     void *cookie)
{
  REALM *nr = NULL;
  struct resp_opaque  *opaque = (struct resp_opaque *) cookie;


  /*xxx There's a race if this is called in two threads for the
    same realm. Imagine if the home pool is not found in either
    thread, is inserted in one thread and then the second
    thread's insert fails. The second thread will fail. Probably
    not a huge deal because a retransmit will make the world
    great again.*/
  if (tid_resp_get_result(resp) != TID_SUCCESS) {
    size_t err_msg_len;
    opaque->result = tid_resp_get_result(resp);
    memset(opaque->err_msg, 0, sizeof(opaque->err_msg));
    if (tid_resp_get_err_msg(resp)) {
      TR_NAME *err_msg = tid_resp_get_err_msg(resp);
      err_msg_len = err_msg->len+1;
      if (err_msg_len > sizeof(opaque->err_msg))
	err_msg_len = sizeof(opaque->err_msg);
      strlcpy(opaque->err_msg, err_msg->buf, err_msg_len);
    }
    return;
  }
		
  nr = talloc_zero(NULL, REALM);
  if (nr == NULL) goto error;
  nr->name = talloc_move(nr, &opaque->fr_realm_name);
  nr->auth_pool = servers_to_pool(inst, resp);
  if (!realm_realm_add(nr, NULL)) goto error;
  opaque->output_realm = nr;
		
		
  return;
		
 error:
  if (nr)
    talloc_free(nr);
  return;
}
		

REALM *tr_query_realm(const char *q_realm,
		      const char  *q_community,
		      const char *q_rprealm,
		      const char *q_trustrouter,
		      unsigned int q_trport)
{
  int conn = 0;
  int rc;
  gss_ctx_id_t gssctx;
  struct resp_opaque cookie;

  /* clear the cookie structure */
  memset (&cookie, 0, sizeof(struct resp_opaque));
  if (NULL == q_realm)
    return NULL;

  cookie.fr_realm_name = talloc_asprintf(NULL,
					  "%s%%%s",
					  q_community, q_realm);
  cookie.output_realm = realm_find(cookie.fr_realm_name);
  if (cookie.output_realm) {
    talloc_free(cookie.fr_realm_name);
    return cookie.output_realm;
  }
    
  /* Set-up TID connection */
  DEBUG2("Openning TIDC connection to %s:%u", q_trustrouter, q_trport);
  if (-1 == (conn = tidc_open_connection(global_tidc, (char *)q_trustrouter, q_trport, &gssctx))) {
    /* Handle error */
    DEBUG2("Error in tidc_open_connection.\n");
    goto cleanup;
  }

  /* Send a TID request */
  if (0 > (rc = tidc_send_request(global_tidc, conn, gssctx, (char *)q_rprealm, 
				  (char *) q_realm, (char *)q_community, 
				  &tr_response_func, &cookie))) {
    /* Handle error */
    DEBUG2("Error in tidc_send_request, rc = %d.\n", rc);
    goto cleanup;
  }

 cleanup:
  if (cookie.fr_realm_name)
    talloc_free(cookie.fr_realm_name);
  return cookie.output_realm;
}
