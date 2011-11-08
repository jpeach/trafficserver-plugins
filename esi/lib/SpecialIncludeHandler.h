#ifndef _ESI_SPECIAL_INCLUDE_HANDLER

#define _ESI_SPECIAL_INCLUDE_HANDLER

#include "HttpDataFetcher.h"
#include "Variables.h"
#include "Expression.h"

namespace EsiLib {

class SpecialIncludeHandler {

public:

  SpecialIncludeHandler(Variables &esi_vars,
                        Expression &esi_expr, HttpDataFetcher &http_fetcher)
    : _esi_vars(esi_vars), _esi_expr(esi_expr), _http_fetcher(http_fetcher) {
  }

  virtual int handleInclude(const char *data, int data_len) = 0;

  virtual void handleParseComplete() = 0;

  /** trivial implementation */
  virtual DataStatus getIncludeStatus(int include_id) {
    const char *data;
    int data_len;
    return getData(include_id, data, data_len) ? STATUS_DATA_AVAILABLE : STATUS_ERROR;
  }

  virtual bool getData(int include_id, const char *&data, int &data_len) = 0;

  virtual void getFooter(const char *&footer, int &footer_len) {
    footer_len = 0;
  }

  virtual ~SpecialIncludeHandler() { };

protected:

  Variables &_esi_vars;
  Expression &_esi_expr;
  HttpDataFetcher &_http_fetcher;

};

};

#endif
