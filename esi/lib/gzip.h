#ifndef _GZIP_H

#define _GZIP_H 

#include <string>
#include <list>

namespace EsiLib {

struct ByteBlock {
  const char *data;
  int data_len;
  ByteBlock(const char *d = 0, int d_len = 0) : data(d), data_len(d_len) { };
};

typedef std::list<ByteBlock> ByteBlockList;

bool gzip(const ByteBlockList& blocks, std::string &cdata);

inline bool gzip(const char *data, int data_len, std::string &cdata) {
  ByteBlockList blocks;
  blocks.push_back(ByteBlock(data, data_len));
  return gzip(blocks, cdata);
}

typedef std::list<std::string> BufferList;

bool gunzip(const char *data, int data_len, BufferList &buf_list);

}

#endif // _GZIP_H
