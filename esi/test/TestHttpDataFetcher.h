#ifndef _TEST_HTTP_DATA_FETCHER_H
#define _TEST_HTTP_DATA_FETCHER_H

#include <string>

#include "HttpDataFetcher.h"

class TestHttpDataFetcher : public HttpDataFetcher
{
  
public:
  
  TestHttpDataFetcher() :  _n_pending_requests(0), _return_data(true) { }
  
  bool addFetchRequest(const std::string &url, FetchedDataProcessor *callback_obj = 0) {
    ++_n_pending_requests;
    return true;
  }

  DataStatus getRequestStatus(const std::string &url) const {
    if (_return_data) {
      return STATUS_DATA_AVAILABLE;
    }
    --(const_cast<int &>(_n_pending_requests));
    return STATUS_ERROR;
  }

  int getNumPendingRequests() const { return _n_pending_requests; };

  bool getContent(const std::string &url, const char *&content, int &content_len) const {
    TestHttpDataFetcher &curr_obj = const_cast<TestHttpDataFetcher &>(*this);
    --curr_obj._n_pending_requests;
    if (_return_data) {
      curr_obj._data.clear();
      curr_obj._data.append(">>>>> Content for URL [");
      curr_obj._data.append(url);
      curr_obj._data.append("] <<<<<");
      content = curr_obj._data.data();
      content_len = curr_obj._data.size();
      return true;
    }
    return false;
  }

  void setReturnData(bool rd) { _return_data = rd; };

  bool getReturnData() const { return _return_data; };

private:
  int _n_pending_requests;
  std::string _data;
  bool _return_data;
  
};

#endif
