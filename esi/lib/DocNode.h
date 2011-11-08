#ifndef _ESI_DOC_NODE_H
#define _ESI_DOC_NODE_H

#include <stdint.h>
#include <list>
#include <string>

#include "Attribute.h"

namespace EsiLib {

struct DocNode;

class DocNodeList : public std::list<DocNode> {

public:

  inline void pack(std::string &buffer, bool retain_buffer_data = false) const {
    if (!retain_buffer_data) {
      buffer.clear();
    }
    packToBuffer(buffer);
  }

  inline std::string pack() const {
    std::string buffer("");
    pack(buffer);
    return buffer;
  }
  
  bool unpack(const char *data, int data_len);
  
  inline bool unpack(const std::string &data) {
    return unpack(data.data(), data.size());
  }

private:

  void packToBuffer(std::string &buffer) const;
  
  friend class DocNode; // to use the method above

};


class DocNode
{
  
public:

  typedef int32_t TYPE;
  static const TYPE TYPE_UNKNOWN;
  static const TYPE TYPE_PRE;
  static const TYPE TYPE_INCLUDE;
  static const TYPE TYPE_COMMENT;
  static const TYPE TYPE_REMOVE;
  static const TYPE TYPE_VARS;
  static const TYPE TYPE_CHOOSE;
  static const TYPE TYPE_WHEN;
  static const TYPE TYPE_OTHERWISE;
  static const TYPE TYPE_TRY;
  static const TYPE TYPE_ATTEMPT;
  static const TYPE TYPE_EXCEPT;
  static const TYPE TYPE_HTML_COMMENT;
  static const TYPE TYPE_SPECIAL_INCLUDE;

  // Use with care - only types defined above will have valid names 
  static const char *type_names_[];

  TYPE type;
  const char *data;
  int32_t data_len;

  AttributeList attr_list;

  DocNodeList child_nodes;

  DocNode(TYPE _type = TYPE_UNKNOWN, const char *_data = 0, int32_t _data_len = 0) 
    : type(_type), data(_data), data_len(_data_len) { };

  void pack(std::string &buffer) const;

  bool unpack(const char *data, int data_len, int &node_len);

private:

  static const char VERSION;

};

};

#endif // _ESI_DOC_NODE_H
