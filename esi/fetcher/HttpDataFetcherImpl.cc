#include "HttpDataFetcherImpl.h"
#include "Utils.h"

#include <arpa/inet.h>

using std::string;
using namespace EsiLib;

const int HttpDataFetcherImpl::FETCH_EVENT_ID_BASE = 10000;

inline void HttpDataFetcherImpl::_release(RequestData &req_data) {
  if (req_data.bufp) {
    if (req_data.hdr_loc) {
      INKHandleMLocRelease(req_data.bufp, INK_NULL_MLOC, req_data.hdr_loc);
      req_data.hdr_loc = 0;
    }
    INKMBufferDestroy(req_data.bufp);
    req_data.bufp = 0;
  }
}

HttpDataFetcherImpl::HttpDataFetcherImpl(INKCont contp, unsigned int client_ip, int client_port,
                                         const char *debug_tag)
  : _contp(contp), _debug_tag(debug_tag), _n_pending_requests(0), _curr_event_id_base(FETCH_EVENT_ID_BASE),
    _headers_str(""), _client_ip(client_ip), _client_port(client_port) {
  _http_parser = INKHttpParserCreate();
}

HttpDataFetcherImpl::~HttpDataFetcherImpl() { 
  clear(); 
  INKHttpParserDestroy(_http_parser); 
}

inline void
HttpDataFetcherImpl::_buildHeadersString() {
  INKDebug(_debug_tag.c_str(), "[%s] Building header string...", __FUNCTION__);
  _headers_str.clear();
  for (StringHash::const_iterator iter = _headers.begin(); iter != _headers.end(); ++iter) {
    _headers_str.append(iter->first);
    _headers_str.append(": ");
    _headers_str.append(iter->second);
    _headers_str += "\r\n";
  }
}

void
HttpDataFetcherImpl::_createRequest(std::string &http_req, const string &url) {
  http_req.assign("GET ");
  http_req.append(url);
  http_req.append(" HTTP/1.0\r\n");
  if (_headers.size()) {
    if (!_headers_str.size()) {
      _buildHeadersString();
    }
    http_req.append(_headers_str);
  }
  http_req.append("\r\n");
}

bool
HttpDataFetcherImpl::addFetchRequest(const string &url, FetchedDataProcessor *callback_obj /* = 0 */) {
  // do we already have a request for this?
  std::pair<UrlToContentMap::iterator, bool> insert_result = 
    _pages.insert(UrlToContentMap::value_type(url, RequestData()));
  if (callback_obj) {
    ((insert_result.first)->second).callback_objects.push_back(callback_obj);
  }
  if (!insert_result.second) {
    INKDebug(_debug_tag.c_str(), "[%s] Fetch request for url [%.*s] already added", __FUNCTION__,
             url.size(), url.data());
    return true;
  }
  
  string http_req;
  _createRequest(http_req, url);

  INKFetchEvent event_ids;
  event_ids.success_event_id = _curr_event_id_base;
  event_ids.failure_event_id = _curr_event_id_base + 1;
  event_ids.timeout_event_id = _curr_event_id_base + 2;
  _curr_event_id_base += 3;

  if (INKFetchUrl(http_req.data(), http_req.size(), _client_ip, _client_port, _contp, AFTER_BODY,
                  event_ids) == INK_ERROR) {
    INKError("Failed to add fetch request for URL [%.*s]", url.size(), url.data());
    return false;
  }
  
  INKDebug(_debug_tag.c_str(), "[%s] Successfully added fetch request for URL [%.*s]",
           __FUNCTION__, url.size(), url.data());
  _page_entry_lookup.push_back(insert_result.first);
  ++_n_pending_requests;
  return true;
}

bool
HttpDataFetcherImpl::_isFetchEvent(INKEvent event, int &base_event_id) const {
  base_event_id = _getBaseEventId(event);
  if ((base_event_id < 0) || (base_event_id >= static_cast<int>(_page_entry_lookup.size()))) {
    INKDebug(_debug_tag.c_str(), "[%s] Event id %d not within fetch event id range [%d, %d)",
             __FUNCTION__, event, FETCH_EVENT_ID_BASE, FETCH_EVENT_ID_BASE + (_page_entry_lookup.size() * 3));
    return false;
  }
  return true;
}

bool
HttpDataFetcherImpl::handleFetchEvent(INKEvent event, void *edata) {
  int base_event_id;
  if (!_isFetchEvent(event, base_event_id)) {
    INKError("[%s] Event %d is not a fetch event", __FUNCTION__, event);
    return false;
  }

  UrlToContentMap::iterator &req_entry = _page_entry_lookup[base_event_id];
  const string &req_str = req_entry->first;
  RequestData &req_data = req_entry->second;

  if (req_data.complete) {
    // can only happen if there's a bug in this or fetch API code
    INKError("[%s] URL [%s] already completed; Retaining original data", __FUNCTION__, req_str.c_str());
    return false;
  }

  --_n_pending_requests;
  req_data.complete = true;

  int event_id = (static_cast<int>(event) - FETCH_EVENT_ID_BASE) % 3;
  if (event_id != 0) { // failure or timeout
    INKError("[%s] Received failure/timeout event id %d for request [%.*s]",
             __FUNCTION__, event_id, req_str.size(), req_str.data());
    return true;
  }

  int page_data_len;
  const char *page_data = INKFetchRespGet(static_cast<INKHttpTxn>(edata), &page_data_len);
  req_data.response.assign(page_data, page_data_len);
  bool valid_data_received = false;
  const char *startptr = req_data.response.data(), *endptr = startptr + page_data_len;

  req_data.bufp = INKMBufferCreate();
  req_data.hdr_loc = INKHttpHdrCreate(req_data.bufp);
  INKHttpHdrTypeSet(req_data.bufp, req_data.hdr_loc, INK_HTTP_TYPE_RESPONSE);
  INKHttpParserClear(_http_parser);
  
  if (INKHttpHdrParseResp(_http_parser, req_data.bufp, req_data.hdr_loc, &startptr, endptr) == INK_PARSE_DONE) {
    INKHttpStatus resp_status = INKHttpHdrStatusGet(req_data.bufp, req_data.hdr_loc);
    if (resp_status == INK_HTTP_STATUS_OK) {
      valid_data_received = true;
      req_data.body_len = endptr - startptr;
      req_data.body = startptr;
      INKDebug(_debug_tag.c_str(),
               "[%s] Inserted page data of size %d starting with [%.6s] for request [%s]", __FUNCTION__,
               req_data.body_len, (req_data.body_len ? req_data.body : "(null)"), req_str.c_str());
      for (CallbackObjectList::iterator list_iter = req_data.callback_objects.begin();
           list_iter != req_data.callback_objects.end(); ++list_iter) {
        (*list_iter)->processData(req_str.data(), req_str.size(), req_data.body, req_data.body_len);
      }
    } else {
      INKDebug(_debug_tag.c_str(), "[%s] Received non-OK status %d for request [%.*s]",
               __FUNCTION__, resp_status, req_str.size(), req_str.data());
    } 
  } else {
    INKDebug(_debug_tag.c_str(), "[%s] Could not parse response for request [%.*s]",
             __FUNCTION__, req_str.size(), req_str.data());
  }

  if (!valid_data_received) {
    _release(req_data);
    req_data.response.clear();
  }

  return true;
}

bool
HttpDataFetcherImpl::getData(const string &url, ResponseData &resp_data) const {
  UrlToContentMap::const_iterator iter = _pages.find(url);
  if (iter == _pages.end()) {
    INKError("Content being requested for unregistered URL [%.*s]", url.size(), url.data());
    return false;
  }
  const RequestData &req_data = iter->second; // handy reference
  if (!req_data.complete) {
    // request not completed yet
    INKError("Request for URL [%.*s] not complete", url.size(), url.data());
    return false;
  }
  if (req_data.response.empty()) {
    // did not receive valid data
    INKError("No valid data received for URL [%.*s]; returning empty data to be safe", url.size(), url.data());
    resp_data.clear();
    return false;
  }
  resp_data.set(req_data.body, req_data.body_len, req_data.bufp, req_data.hdr_loc);
  INKDebug(_debug_tag.c_str(), "[%s] Found data for URL [%.*s] of size %d starting with [%.5s]", 
           __FUNCTION__, url.size(), url.data(), req_data.body_len, req_data.body);
  return true;
}

void
HttpDataFetcherImpl::clear() {
  for (UrlToContentMap::iterator iter = _pages.begin(); iter != _pages.end(); ++iter) {
    _release(iter->second);
  }
  _n_pending_requests = 0;
  _pages.clear();
  _page_entry_lookup.clear();
  _headers_str.clear();
  _headers.clear();
  _curr_event_id_base = FETCH_EVENT_ID_BASE;
}

DataStatus
HttpDataFetcherImpl::getRequestStatus(const string &url) const {
  UrlToContentMap::const_iterator iter = _pages.find(url);
  if (iter == _pages.end()) {
    INKError("Status being requested for unregistered URL [%.*s]", url.size(), url.data());
    return STATUS_ERROR;
  }
  if (!(iter->second).complete) {
    return STATUS_DATA_PENDING;
  }
  if ((iter->second).response.empty()) {
    return STATUS_ERROR;
  }
  return STATUS_DATA_AVAILABLE;
}

void
HttpDataFetcherImpl::useHeader(const HttpHeader &header) {
  if (Utils::areEqual(header.name, header.name_len,
                      INK_MIME_FIELD_ACCEPT_ENCODING, INK_MIME_LEN_ACCEPT_ENCODING)) {
    return;
  }
  string name(header.name, header.name_len);
  string value(header.value, header.value_len);
  std::pair<StringHash::iterator, bool> result = _headers.insert(StringHash::value_type(name, value));
  if (!result.second) {
    result.first->second = value;
  }
  if (_headers_str.size()) { // rebuild
    _buildHeadersString();
  }
}

void
HttpDataFetcherImpl::useHeaders(const HttpHeaderList &headers) {
  for (HttpHeaderList::const_iterator iter = headers.begin(); iter != headers.end(); ++iter) {
    useHeader(*iter);
  }
}
