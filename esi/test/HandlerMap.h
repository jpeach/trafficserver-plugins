#ifndef _HANDLER_MAP_H

#define _HANDLER_MAP_H

#include <string>
#include <map>

#include "StubIncludeHandler.h"

typedef std::map<std::string, StubIncludeHandler *> HandlerMap;

extern HandlerMap gHandlerMap;

#endif
