#ifndef _STRING_HASH_H

#define _STRING_HASH_H

#include <string>
#include <ext/hash_map>

namespace EsiLib {

struct StringHasher {
  inline size_t operator ()(const std::string &str) const {
    return __gnu_cxx::hash<const char *>()(str.c_str());
  };
};

typedef __gnu_cxx::hash_map<std::string, std::string, StringHasher> StringHash;

template<typename T>
class StringKeyHash : public __gnu_cxx::hash_map<std::string, T, StringHasher> {
};

};

#endif // _STRING_HASH_H
