#ifndef _ESI_HTTP_HEADER_H

#define _ESI_HTTP_HEADER_H

#include <list>

namespace EsiLib {

struct HttpHeader {
  const char *name;
  int name_len;
  const char *value;
  int value_len;
  HttpHeader(const char *n = 0, int n_len = -1, const char *v = 0, int v_len = -1) 
    : name(n), name_len(n_len), value(v), value_len(v_len) { };
};

typedef std::list<HttpHeader> HttpHeaderList;

};

#endif // _ESI_HTTP_HEADER_H
