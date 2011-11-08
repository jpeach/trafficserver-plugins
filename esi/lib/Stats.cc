#include "Stats.h"

using namespace EsiLib;

const char *Stats::STAT_NAMES[Stats::MAX_STAT_ENUM] = { 
  "esi.n_os_docs",
  "esi.n_cache_docs",
  "esi.n_parse_errs",
  "esi.n_includes",
  "esi.n_include_errs",
  "esi.n_spcl_includes",
  "esi.n_spcl_include_errs"
};

static uint32_t g_stat_indices[Stats::MAX_STAT_ENUM];
static StatSystem *g_system = 0;

void Stats::init(StatSystem *system) {
  g_system = system;
  if (g_system) {
    for (int i = 0; i < Stats::MAX_STAT_ENUM; ++i) {
      if (!g_system->create(Stats::STAT_NAMES[i], &g_stat_indices[i])) {
        Utils::ERROR_LOG("[%s] Unable to create stat [%s]", __FUNCTION__, Stats::STAT_NAMES[i]);
      }
    }
  }
}

void Stats::increment(Stats::STAT st, int step /* = 1 */) {
  if (g_system) {
    if (!g_system->increment(g_stat_indices[st], step)) {
      Utils::ERROR_LOG("[%s] Unable to increment stat [%s] by step [%d]", __FUNCTION__, step,
                       Stats::STAT_NAMES[st]);
    }
  }
}
