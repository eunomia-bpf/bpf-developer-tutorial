#ifndef __SCX_NEST_H
#define __SCX_NEST_H

enum nest_stat_group {
	STAT_GRP_WAKEUP,
	STAT_GRP_NEST,
	STAT_GRP_CONSUME,
};

#define NEST_STAT(__stat) BPFSTAT_##__stat
#define NEST_ST(__stat, __grp, __desc) NEST_STAT(__stat),
enum nest_stat_idx {
#include "scx_nest_stats_table.h"
	NEST_ST(NR, 0, 0)
};
#undef NEST_ST

#endif /* __SCX_NEST_H */
