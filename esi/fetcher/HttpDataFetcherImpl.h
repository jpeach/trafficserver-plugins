#ifndef _HTTP_DATA_FETCHER_IMPL_H
#define _HTTP_DATA_FETCHER_IMPL_H

#include <string>
#include <list>
#include <vector>

#include "InkAPI.h"
#include "StringHash.h"
#include "HttpHeader.h"
#include "HttpDataFetcher.h"

class HttpDataFetcherImpl : public HttpDataFetcher
{

public:

  HttpDataFetcherImpl(INKCont contp, unsigned int client_ip, int client_port, const char *debug_tag);

  void useHeader(const EsiLib::HttpHeader &header);
  
  void useHeaders(const EsiLib::HttpHeaderList &headers);

  bool addFetchRequest(const std::string &url, FetchedDataProcessor *callback_obj = 0);
  
  bool handleFetchEvent(INKEvent event, void *edata);

  bool isFetchEvent(INKEvent event) const {
    int base_event_id;
    return _isFetchEvent(event, base_event_id);
  }

  bool isFetchComplete() const { return (_n_pending_requests == 0); };

  DataStatus getRequestStatus(const std::string &url) const;

  int getNumPendingRequests() const { return _n_pending_requests; };

  // used to return data to callers
  struct ResponseData {
    const char *content;
    int content_len;
    INKMBuffer bufp;
    INKMLoc hdr_loc;
    ResponseData() { set(0, 0, 0, 0); }
    inline void set(const char *c, int clen, INKMBuffer b, INKMLoc loc);
    void clear() { set(0, 0, 0, 0); }
  };

  bool getData(const std::string &url, ResponseData &resp_data) const;

  bool getContent(const std::string &url, const char *&content, int &content_len) const {
    ResponseData resp;
    if (getData(url, resp)) {
      content = resp.content;
      content_len = resp.content_len;
      return true;
    }
    return false;
  }

  void clear();

  ~HttpDataFetcherImpl();

private:
  
  INKCont _contp;
  std::string _debug_tag;

  typedef std::list<FetchedDataProcessor *> CallbackObjectList;
 
  // used to track a request that was made
  struct RequestData {
    std::string response;
    const char *body;
    int body_len;
    CallbackObjectList callback_objects;
    bool complete;
    INKMBuffer bufp;
    INKMLoc hdr_loc;
    RequestData() : body(0), body_len(0), complete(false), bufp(0), hdr_loc(0) { };
  };

  typedef __gnu_cxx::hash_map<std::string, RequestData, EsiLib::StringHasher> UrlToContentMap;
  UrlToContentMap _pages;

  typedef std::vector<UrlToContentMap::iterator> IteratorArray;
  IteratorArray _page_entry_lookup; // used to map event ids to requests

  int _n_pending_requests;
  int _curr_event_id_base;
  INKHttpParser _http_parser;

  static const int FETCH_EVENT_ID_BASE;

  int _getBaseEventId(INKEvent event) const {
    return (static_cast<int>(event) - FETCH_EVENT_ID_BASE) / 3; // integer division
  }

  bool _isFetchEvent(INKEvent event, int &base_event_id) const;

  EsiLib::StringHash _headers;
  std::string _headers_str;
  
  inline void _buildHeadersString();
  void _createRequest(std::string &http_req, const std::string &url);
  inline void _release(RequestData &req_data);

  unsigned int _client_ip;
  int _client_port;
};

inline void
HttpDataFetcherImpl::ResponseData::set(const char *c, int clen, INKMBuffer b, INKMLoc loc) {
  content = c;
  content_len = clen;
  bufp = b;
  hdr_loc = loc;
}

#endif
