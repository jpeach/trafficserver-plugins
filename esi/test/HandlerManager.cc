#include "HandlerManager.h"
#include "HandlerMap.h"

using namespace EsiLib;

void
HandlerManager::loadObjects(const Utils::KeyValueMap &handlers) {
}

SpecialIncludeHandler *
HandlerManager::getHandler(Variables &esi_vars, Expression &esi_expr, HttpDataFetcher &fetcher,
                           const std::string &id) const {
  StubIncludeHandler *handler = new StubIncludeHandler(esi_vars, esi_expr, fetcher);
  gHandlerMap[id] = handler;
  return handler;
}

HandlerManager::~HandlerManager() {
}
