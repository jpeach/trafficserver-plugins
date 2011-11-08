#ifndef _HTTP_DATA_FETCHER_H
#define _HTTP_DATA_FETCHER_H

#include <string>

#include "FetchedDataProcessor.h"

enum DataStatus { STATUS_ERROR = -1, STATUS_DATA_AVAILABLE = 0, STATUS_DATA_PENDING = 1  };

class HttpDataFetcher
{

public:

  virtual bool addFetchRequest(const char *url, int url_len, FetchedDataProcessor *callback_obj = 0) {
    return addFetchRequest(std::string(url, url_len), callback_obj);
  }

  virtual bool addFetchRequest(const char *url, FetchedDataProcessor *callback_obj = 0) {
    return addFetchRequest(std::string(url), callback_obj);
  }

  virtual bool addFetchRequest(const std::string &url, FetchedDataProcessor *callback_obj = 0) = 0;

  virtual DataStatus getRequestStatus(const char *url, int url_len) const {
    return getRequestStatus(std::string(url, url_len));
  }

  virtual DataStatus getRequestStatus(const char *url) const {
    return getRequestStatus(std::string(url));
  }

  virtual DataStatus getRequestStatus(const std::string &url) const = 0;

  virtual int getNumPendingRequests() const = 0;

  virtual bool getContent(const char *url, int url_len, const char *&content, int &content_len) const {
    return getContent(std::string(url, url_len), content, content_len);
  }

  virtual bool getContent(const char *url, const char *&content, int &content_len) const {
    return getContent(std::string(url), content, content_len);
  }

  virtual bool getContent(const std::string &url, const char *&content, int &content_len) const = 0;

  virtual ~HttpDataFetcher() { };

};

#endif
