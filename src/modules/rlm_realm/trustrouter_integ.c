#include <trust_router/tid.h>
#include "trustrouter_integ.h"

static TIDC_INSTANCE *global_tidc;
static int tidc_response_received = 0;

int tr_init(void) 
{
  if (NULL == (global_tidc = tidc_create()))
    return -1;
  else
    return 0;
}

static void tr_response_func (TIDC_INSTANCE *tidc, TID_REQ *req, TID_RESP *resp, void *cookie)
{

}


#if 0

static void tr_response_func(UNUSED tpqc_instance *inst,
			     const tpq_resp *response, void *cookie)
{
	home_server *hs = NULL;
	home_pool_t *pool = NULL;
	REALM *nr = NULL;
	char home_pool_name[256];
	fr_ipaddr_t home_server_ip;

	/*xxx There's a race if this is called in two threads for the same realm. Imagine if the home pool is not found in either thread, is inserted in one thread and then the second thread's insert fails. The second thread will fail. Probably not a huge deal because a retransmit will make the world great again.*/
	home_server_ip = /*xxx something from response*/
		hs = home_server_find( home_server_ip, /*xxx port from response*/,
				       /*xxx proto from response*/);
	if (hs) {
		/*confirm that hs is good enough to use; I think this mainly involves making sure we find the key credible. */
		abort();
	} else {
		hs = rad_malloc(sizeof(*hs));
		if (!hs) return;
		memset(hs, 0, sizeof(*hs));
		hs->type = HOME_TYPE_AUTH;
		hs->ipaddr = *home_server_ip;
		hs-> name = /*name from response*/
			hs->hostname = /*name from response*/
			hs->port = /*port from response*/
			hs->proto = /*proto from response*/
			hs->tls = response_to_tls(response);
		if (hs->tls == NULL) goto error;
		if (!realms_home_server_add(hs, NULL, 0))
			goto error;
	}
	strlcpy(home_pool_name, "hp-", sizeof(home_pool_name);
		strlcat(home_pool_name, response->realm,, sizeof(home_pool_name));
		pool = home_pool_byname(home_pool_name, HOME_SERVER_AUTH);
		if (pool == NULL) {
			pool = rad_malloc(sizeof(*pool));
			if (pool == NULL) goto error;
			memset(pool, 0, sizeof(*pool));
			pool->type = HOME_POOL_CLIENT_PORT_BALANCE;
			pool->server_type = HOME_TYPE_AUTH;
			pool->name = strdup(home_pool_name);
			if (pool->name == NULL) goto error;
			pool->num_home_servers = 1;
			pool->servers[0] = hs;
			if (!realms_pool_add(pool)) goto error;
		}
		
		nr = rad_malloc(sizeof (REALM));
		if (nr == NULL) goto error;
		memset(nr, 0, sizeof(REALM));
		nr->name = strdup(response->realm);
		nr->auth_pool = pool;
		if (!realms_realm_add(nr)) goto error;
		
		/*do something with the cookie to let the poor other theread know to go forward*/
		
		return;
		
	error:
		/*What do we do here? We don't actually have a way to delete things from the tree, so we can't free them.
		 */
		/*I guess we could have partial unwinding for the parts we haven't added yet*/

		
#endif

REALM *tr_query_realm(const char *q_realm,
		      const char  *q_community,
		      const char *q_rprealm,
		      const char *q_trustrouter)
{
  int conn = 0;
  int rc;
  gss_ctx_id_t gssctx;
  struct resp_opaque *cookie;

  /* clear the cookie structure */
  cookie = malloc(sizeof(struct resp_opaque));
  memset (cookie, 0, sizeof(struct resp_opaque));

  /* Set-up TID connection */
  if (-1 == (conn = tidc_open_connection(global_tidc, (char *)q_trustrouter, &gssctx))) {
    /* Handle error */
    printf("Error in tidc_open_connection.\n");
    return NULL;
  };

  /* Send a TID request */
  if (0 > (rc = tidc_send_request(global_tidc, conn, gssctx, (char *)q_rprealm, 
				  (char *) q_realm, (char *)q_community, 
				  &tr_response_func, cookie))) {
    /* Handle error */
    printf("Error in tidc_send_request, rc = %d.\n", rc);
    return NULL;
  }
    
  /* Wait for a response */
  while (!tidc_response_received);

  return cookie->output_realm;
}
