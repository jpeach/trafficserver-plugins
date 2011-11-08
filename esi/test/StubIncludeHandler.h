#ifndef _STUB_INCLUDE_HANDLER_H

#define _STUB_INCLUDE_HANDLER_H

#include <list>
#include "SpecialIncludeHandler.h"

class StubIncludeHandler : public EsiLib::SpecialIncludeHandler {

public:

  StubIncludeHandler(EsiLib::Variables &esi_vars, EsiLib::Expression &esi_expr, 
                     HttpDataFetcher &http_fetcher)
    : EsiLib::SpecialIncludeHandler(esi_vars, esi_expr, http_fetcher),
      parseCompleteCalled(false), n_includes(0) {
  }

  int handleInclude(const char *data, int data_len);

  bool parseCompleteCalled;
  void handleParseComplete();
  
  bool getData(int include_id, const char *&data, int &data_len);

  void getFooter(const char *&footer, int &footer_len);
  
  ~StubIncludeHandler();
  
  static bool includeResult;
  static const char *const DATA_PREFIX;
  static const int DATA_PREFIX_SIZE;

  static const char *FOOTER;
  static int FOOTER_SIZE;

private:

  int n_includes;
  std::list<char *> heap_strings;

};

#endif
