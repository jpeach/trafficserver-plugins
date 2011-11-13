#ifndef _ESI_STATS_H

#define _ESI_STATS_H

#include "Utils.h"
#include <ts/ts.h>

namespace EsiLib {

/** interface that stat systems should implement */
class StatSystem {
public:
  virtual void create(int handle) = 0;
  virtual void increment(int handle, TSMgmtInt step = 1) = 0;
  virtual ~StatSystem() { };
};

namespace Stats {

enum STAT { N_OS_DOCS = 0,
            N_CACHE_DOCS = 1,
            N_PARSE_ERRS = 2,
            N_INCLUDES = 3,
            N_INCLUDE_ERRS = 4,
            N_SPCL_INCLUDES = 5,
            N_SPCL_INCLUDE_ERRS = 6,
            MAX_STAT_ENUM = 7 };

extern const char *STAT_NAMES[MAX_STAT_ENUM];
extern int g_stat_indices[Stats::MAX_STAT_ENUM];
extern StatSystem *g_system;

void init(StatSystem *system);

void increment(STAT st, int step = 1);

};

};
              

#endif
