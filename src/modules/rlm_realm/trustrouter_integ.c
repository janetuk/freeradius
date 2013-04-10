#include <trust_router/tid.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

struct resp_opaque {
  REALM *output_realm;
  tid_rc result;
  char err_msg[1024];
  DH *client_dh; /*in*/
};

static fr_tls_server_conf_t *construct_tls( tidc_inst *inst,
					    tid_svr_blk *server)
{
  fr_tls_server_conf_t *tls = rad_malloc(sizeof(*tls));
  unsigned char *key_buf = NULL;
  ssize_t keylen;
  if (tls == NULL)
    goto error;
  memset(tls, 0, sizeof(*tls));
  keylen = tr_compute_dh_key(&key_buf, server->aaa_server_dh->pub_key,
			     inst->priv_dh);
  if (key_len <= 0) {
    DEBUG2("DH error");
    goto error;
  }
  hexbuf = rad_malloc(keylen*2 + 1);
  if (hexbuf == NULL)
    goto error;
  tr_bin2hex(key_buf, keylen, hexbuf,
	     2*keylen + 1);
  tls->psk_password = hexbuf;
  tls->psk_identity = tr_name_strdup(server->key_name);
  tls->cipher_list = "PSK";
  tls->ctx = tls_init_ctx(tls, 1);
  if (tls->ctx == NULL)
    goto error;
  memset(key_buf, 0, keylen);
  free(key_buf);
    return tls;
 error:
    if (key_buf) {
      memset(key_buf, 0, keylen);
      free(key_buf);
    }
    if (hex) {
      memset(hex, 0, keylen*2);
      free(hex);
    }
    if (tls)
      free(tls);
    return NULL;
}

      

  
static void tr_response_func(UNUSED tidc_instance *inst,
			     const tid_req *req, const tid_resp *response,
			     void *cookie)
{
  home_server *hs = NULL;
  tid_srvr_blk *server;
  home_pool_t *pool = NULL;
  REALM *nr = NULL;
  char home_pool_name[256];
  fr_ipaddr_t home_server_ip;
  tr_opaque *opaque = (tr_opaque *) cookie;
  size_t num_servers = 0;

  /*xxx There's a race if this is called in two threads for the
    same realm. Imagine if the home pool is not found in either
    thread, is inserted in one thread and then the second
    thread's insert fails. The second thread will fail. Probably
    not a huge deal because a retransmit will make the world
    great again.*/
  if (resp->rc != TR_SUCCESS) {
    size_t error_len;
    opaque->result = resp->rc;
    memset(opaque->err_msg, 0, sizeof(opaque->err_msg));
    if (resp->err_msg) {
      err_msg_len = resp->err_msg->len+1;
      if (err_msg_len > sizeof(opaque->err_msg))
	err_msg_len = sizeof(opaque->err_msg);
      strlcpy(opaque->err_msg, resp->err_msg->buf, err_msg_len);
    }
    return;
  }
  server = resp->servers;
  while (server) {
    num_servers++;
    server = server->next;
  }
  strlcpy(home_pool_name, "hp-", sizeof(home_pool_name));
  tr_name_strlcat(home_pool_name, response->realm, sizeof(home_pool_name));
  pool = home_pool_byname(home_pool_name, HOME_SERVER_AUTH);
  if (pool == NULL) {
    size_t i = 0;
    pool = rad_malloc(sizeof(*pool) + num_servers *sizeof(HOME_SERVER *));
		  
    if (pool == NULL) goto error;
    memset(pool, 0, sizeof(*pool));
    pool->type = HOME_POOL_CLIENT_PORT_BALANCE;
    pool->server_type = HOME_TYPE_AUTH;
    pool->name = strdup(home_pool_name);
    if (pool->name == NULL) goto error;
    pool->num_home_servers = num_servers;

    server = resp->servers;
    while (server) {
      home_server_ip.af = 4;
      home_server_ip.scope = 0;
      home_server_ip.ipaddr.ip4addr = server->aaa_server_addr;
	  
      hs = home_server_find( home_server_ip, htons(2083),
			     IPPROTO_TCP);
      if (hs) {
	DEBUG2("Found existing home_server %s", hs->name);
      } else {
	hs = rad_malloc(sizeof(*hs));
	if (!hs) return;
	memset(hs, 0, sizeof(*hs));
	hs->type = HOME_TYPE_AUTH;
	hs->ipaddr = home_server_ip;
	hs-> name = 
	  hs->hostname = /*name from response*/
	  hs->port = htons(2083);
	hs->proto = IPPROTO_TCP;
	hs->tls = construct_tls(server, opaque);
	if (hs->tls == NULL) goto error;
	if (!realms_home_server_add(hs, NULL, 0))
	  goto error;
      }
      pool->servers[i++] = hs;
      hs = NULL;
    }
			
    if (!realms_pool_add(pool)) goto error;
    pool_added = 1;
  }
		
  nr = rad_malloc(sizeof (REALM));
  if (nr == NULL) goto error;
  memset(nr, 0, sizeof(REALM));
  nr->name = tr_name_strdup(response->realm);
  nr->auth_pool = pool;
  if (!realms_realm_add(nr)) goto error;
  opaque->realm = nr;
		
		
  return;
		
 error:
  if (hs)
    free(hs);
  if (pool && (!pool_added)) {
    if (pool->name)
      free(pool->name);
    free(pool);
  }
  if (nr)
    free(nr);
  return;
}
		


REALM *tr_query_realm(const char *q_realm, ,
		      const char  *q_community)
{
	/*This function is called when there is no applicable realm to give trust router a chance to query the realm.*/
	
