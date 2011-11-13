#ifndef _ESI_SERVER_INTERCEPT_H

#define _ESI_SERVER_INTERCEPT_H

#include "ts/ts.h"

bool setupServerIntercept(TSHttpTxn txnp);

extern const char *ECHO_HEADER_PREFIX;
extern const char *SERVER_INTERCEPT_HEADER;

extern const int ECHO_HEADER_PREFIX_LEN;
extern const int SERVER_INTERCEPT_HEADER_LEN;

#endif
