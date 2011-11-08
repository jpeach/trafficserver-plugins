#ifndef _ESI_COMPONENT_BASE_H
#define _ESI_COMPONENT_BASE_H

#include <string>

namespace EsiLib {

/** class that has common private characteristics */
class ComponentBase
{

public:

  typedef void (*Debug)(const char *, const char *, ...);
  typedef void (*Error)(const char *, ...);

protected:
  
  ComponentBase(const char *debug_tag, Debug debug_func, Error error_func) 
    : _debug_tag(debug_tag), _debugLog(debug_func), _errorLog(error_func) { };
  
  std::string _debug_tag;
  Debug _debugLog;
  Error _errorLog;
  
  virtual ~ComponentBase() { };

};

};

#endif // _ESI_COMPONENT_BASE_H
