#include "StubIncludeHandler.h"
#include "TestHttpDataFetcher.h"

using namespace EsiLib;

bool StubIncludeHandler::includeResult = true;
const char *const StubIncludeHandler::DATA_PREFIX = "Special data for include id ";
const int StubIncludeHandler::DATA_PREFIX_SIZE = strlen(StubIncludeHandler::DATA_PREFIX);

const char *StubIncludeHandler::FOOTER = 0;
int StubIncludeHandler::FOOTER_SIZE = 0;

int
StubIncludeHandler::handleInclude(const char *data, int data_len) {
  if (includeResult) {
    _http_fetcher.addFetchRequest(data, data_len);
    return ++n_includes;
  }
  return -1;
}

void
StubIncludeHandler::handleParseComplete() {
  parseCompleteCalled = true;
}
  
bool
StubIncludeHandler::getData(int include_id, const char *&data, int &data_len) {
  TestHttpDataFetcher &test_fetcher = dynamic_cast<TestHttpDataFetcher &>(_http_fetcher);
  if (test_fetcher.getReturnData()) {
    char *buf = new char[1024];
    data_len = snprintf(buf, 1024, "%s%d", DATA_PREFIX, include_id);
    data = buf;
    heap_strings.push_back(buf);
    return true;
  }
  return false;
}

void
StubIncludeHandler::getFooter(const char *&footer, int &footer_len) {
  footer = FOOTER;
  footer_len = FOOTER_SIZE;
}
  
StubIncludeHandler::~StubIncludeHandler() {
  for (std::list<char *>::iterator iter = heap_strings.begin(); iter != heap_strings.end(); ++iter) {
    delete[] *iter;
  }
}
