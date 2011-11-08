#ifndef _ESI_ATTRIBUTE_H
#define _ESI_ATTRIBUTE_H

#include <list>

namespace EsiLib {

struct Attribute {
  const char *name;
  int32_t name_len;
  const char *value;
  int32_t value_len;
  Attribute(const char *n = 0, int32_t n_len = 0, const char *v = 0, int32_t v_len = 0)
    : name(n), name_len(n_len), value(v), value_len(v_len) { };
};

typedef std::list<Attribute> AttributeList;

};

#endif // _ESI_ATTRIBUTE_H
