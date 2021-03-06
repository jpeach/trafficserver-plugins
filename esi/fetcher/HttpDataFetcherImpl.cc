/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include "HttpDataFetcherImpl.h"
#include "Utils.h"

#include <arpa/inet.h>

using std::string;
using namespace EsiLib;

const int HttpDataFetcherImpl::FETCH_EVENT_ID_BASE = 10000;

inline void HttpDataFetcherImpl::_release(RequestData &req_data) {
  if (req_data.bufp) {
    if (req_data.hdr_loc) {
      TSHandleMLocRelease(req_data.bufp, TS_NULL_MLOC, req_data.hdr_loc);
      req_data.hdr_loc = 0;
    }
    TSMBufferDestroy(req_data.bufp);
    req_data.bufp = 0;
  }
}

HttpDataFetcherImpl::HttpDataFetcherImpl(TSCont contp,sockaddr const* client_addr,
                                         const char *debug_tag)
  : _contp(contp), _debug_tag(debug_tag), _n_pending_requests(0), _curr_event_id_base(FETCH_EVENT_ID_BASE),
    _headers_str(""),_client_addr(client_addr) {
  _http_parser = TSHttpParserCreate();
}

HttpDataFetcherImpl::~HttpDataFetcherImpl() { 
  clear(); 
  TSHttpParserDestroy(_http_parser); 
}

inline void
HttpDataFetcherImpl::_buildHeadersString() {
  TSDebug(_debug_tag.c_str(), "[%s] Building header string...", __FUNCTION__);
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
    TSDebug(_debug_tag.c_str(), "[%s] Fetch request for url [%.*s] already added", __FUNCTION__,
             url.size(), url.data());
    return true;
  }
  
  string http_req;
  _createRequest(http_req, url);

  TSFetchEvent event_ids;
  event_ids.success_event_id = _curr_event_id_base;
  event_ids.failure_event_id = _curr_event_id_base + 1;
  event_ids.timeout_event_id = _curr_event_id_base + 2;
  _curr_event_id_base += 3;

  if (TSFetchUrl(http_req.data(), http_req.size(), _client_addr, _contp, AFTER_BODY,
                  event_ids) == TS_ERROR) {
    TSError("Failed to add fetch request for URL [%.*s]", url.size(), url.data());
    return false;
  }
  
  TSDebug(_debug_tag.c_str(), "[%s] Successfully added fetch request for URL [%.*s]",
           __FUNCTION__, url.size(), url.data());
  _page_entry_lookup.push_back(insert_result.first);
  ++_n_pending_requests;
  return true;
}

bool
HttpDataFetcherImpl::_isFetchEvent(TSEvent event, int &base_event_id) const {
  base_event_id = _getBaseEventId(event);
  if ((base_event_id < 0) || (base_event_id >= static_cast<int>(_page_entry_lookup.size()))) {
    TSDebug(_debug_tag.c_str(), "[%s] Event id %d not within fetch event id range [%d, %d)",
             __FUNCTION__, event, FETCH_EVENT_ID_BASE, FETCH_EVENT_ID_BASE + (_page_entry_lookup.size() * 3));
    return false;
  }
  return true;
}

bool
HttpDataFetcherImpl::handleFetchEvent(TSEvent event, void *edata) {
  int base_event_id;
  if (!_isFetchEvent(event, base_event_id)) {
    TSError("[%s] Event %d is not a fetch event", __FUNCTION__, event);
    return false;
  }

  UrlToContentMap::iterator &req_entry = _page_entry_lookup[base_event_id];
  const string &req_str = req_entry->first;
  RequestData &req_data = req_entry->second;

  if (req_data.complete) {
    // can only happen if there's a bug in this or fetch API code
    TSError("[%s] URL [%s] already completed; Retaining original data", __FUNCTION__, req_str.c_str());
    return false;
  }

  --_n_pending_requests;
  req_data.complete = true;

  int event_id = (static_cast<int>(event) - FETCH_EVENT_ID_BASE) % 3;
  if (event_id != 0) { // failure or timeout
    TSError("[%s] Received failure/timeout event id %d for request [%.*s]",
             __FUNCTION__, event_id, req_str.size(), req_str.data());
    return true;
  }

  int page_data_len;
  const char *page_data = TSFetchRespGet(static_cast<TSHttpTxn>(edata), &page_data_len);
  req_data.response.assign(page_data, page_data_len);
  bool valid_data_received = false;
  const char *startptr = req_data.response.data(), *endptr = startptr + page_data_len;

  req_data.bufp = TSMBufferCreate();
  req_data.hdr_loc = TSHttpHdrCreate(req_data.bufp);
  TSHttpHdrTypeSet(req_data.bufp, req_data.hdr_loc, TS_HTTP_TYPE_RESPONSE);
  TSHttpParserClear(_http_parser);
  
  if (TSHttpHdrParseResp(_http_parser, req_data.bufp, req_data.hdr_loc, &startptr, endptr) == TS_PARSE_DONE) {
    TSHttpStatus resp_status = TSHttpHdrStatusGet(req_data.bufp, req_data.hdr_loc);
    if (resp_status == TS_HTTP_STATUS_OK) {
      valid_data_received = true;
      req_data.body_len = endptr - startptr;
      req_data.body = startptr;
      TSDebug(_debug_tag.c_str(),
               "[%s] Inserted page data of size %d starting with [%.6s] for request [%s]", __FUNCTION__,
               req_data.body_len, (req_data.body_len ? req_data.body : "(null)"), req_str.c_str());
      for (CallbackObjectList::iterator list_iter = req_data.callback_objects.begin();
           list_iter != req_data.callback_objects.end(); ++list_iter) {
        (*list_iter)->processData(req_str.data(), req_str.size(), req_data.body, req_data.body_len);
      }
    } else {
      TSDebug(_debug_tag.c_str(), "[%s] Received non-OK status %d for request [%.*s]",
               __FUNCTION__, resp_status, req_str.size(), req_str.data());
    } 
  } else {
    TSDebug(_debug_tag.c_str(), "[%s] Could not parse response for request [%.*s]",
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
    TSError("Content being requested for unregistered URL [%.*s]", url.size(), url.data());
    return false;
  }
  const RequestData &req_data = iter->second; // handy reference
  if (!req_data.complete) {
    // request not completed yet
    TSError("Request for URL [%.*s] not complete", url.size(), url.data());
    return false;
  }
  if (req_data.response.empty()) {
    // did not receive valid data
    TSError("No valid data received for URL [%.*s]; returning empty data to be safe", url.size(), url.data());
    resp_data.clear();
    return false;
  }
  resp_data.set(req_data.body, req_data.body_len, req_data.bufp, req_data.hdr_loc);
  TSDebug(_debug_tag.c_str(), "[%s] Found data for URL [%.*s] of size %d starting with [%.5s]", 
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
    TSError("Status being requested for unregistered URL [%.*s]", url.size(), url.data());
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
                      TS_MIME_FIELD_ACCEPT_ENCODING, TS_MIME_LEN_ACCEPT_ENCODING)) {
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
