
#ifndef TRUSTROUTER_INTEG_H
#define TRUSTROUTER_INTEG_H

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <trust_router/tid.h>

struct resp_opaque {
  REALM *output_realm;
  TID_RC result;
  char err_msg[1024];
};          
 
REALM *tr_query_realm(const char *q_realm,
		      const char  *q_community,
		      const char *q_rprealm,
		      const char *q_trustrouter);

int tr_init(void);

#endif
