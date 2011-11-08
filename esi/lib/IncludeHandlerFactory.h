#ifndef _INCLUDE_HANDLER_FACTORY_H

#define _INCLUDE_HANDLER_FACTORY_H

#include <string>
#include "SpecialIncludeHandler.h"

#ifdef __cplusplus
extern "C" {
#endif

EsiLib::SpecialIncludeHandler *createSpecialIncludeHandler(EsiLib::Variables &esi_vars,
                                                           EsiLib::Expression &esi_expr,
                                                           HttpDataFetcher &fetcher,
                                                           const std::string &id);
  
#ifdef __cplusplus
}
#endif

namespace EsiLib {

typedef SpecialIncludeHandler *(*SpecialIncludeHandlerCreator)(Variables &esi_vars,
                                                               Expression &esi_expr,
                                                               HttpDataFetcher &fetcher,
                                                               const std::string &id);

};

#endif

