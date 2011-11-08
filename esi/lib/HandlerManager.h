#ifndef _HANDLER_MANAGER_H

#define _HANDLER_MANAGER_H

#include <string>
#include <map>

#include "ComponentBase.h"
#include "Utils.h"
#include "SpecialIncludeHandler.h"
#include "IncludeHandlerFactory.h"
#include "Variables.h"
#include "HttpDataFetcher.h"

namespace EsiLib {

class HandlerManager : protected ComponentBase {

public:

  HandlerManager(const char *debug_tag, Debug debug_func, Error error_func) :
    ComponentBase(debug_tag, debug_func, error_func) {
  };

  void loadObjects(const Utils::KeyValueMap &handlers);

  SpecialIncludeHandler *getHandler(Variables &esi_vars, Expression &esi_expr,
                                    HttpDataFetcher &http_fetcher, const std::string &id) const;

  ~HandlerManager();

private:

  typedef std::map<std::string, SpecialIncludeHandlerCreator> FunctionHandleMap;

  struct ModuleHandles {
    void *object;
    SpecialIncludeHandlerCreator function;
    ModuleHandles(void *o = 0, SpecialIncludeHandlerCreator f = 0) : object(o), function(f) { };
  };

  typedef std::map<std::string, ModuleHandles> ModuleHandleMap;

  FunctionHandleMap _id_to_function_map;
  ModuleHandleMap _path_to_module_map;

  static const char *const FACTORY_FUNCTION_NAME;
};

};

#endif
