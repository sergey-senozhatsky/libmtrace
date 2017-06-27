#ifndef __OPTIONS_H
#define __OPTIONS_H

#include <stdio.h>

#define INIT_BUF_SZ		(2 * 1024 * 1024)
#define MAX_FN_NAME_BUF_SZ	4096

#define UNWIND_DEPTH		32

#define MIN_ALIGNMENT	(sizeof(size_t))
#define ALIGN(x, a)	(((x) + (a) - 1) & ~((a) - 1))

#define DEFAULT_PAGE_SIZE	4096

#define OPTS_ALLOC_ONLY_MODE	(1 << 1)
#define OPTS_ALLOC_TOP_MODE	(1 << 2)
#define OPTS_FULL_REPORT_MODE	(1 << 3)
#define OPTS_MEM_GROW_MODE	(1 << 4)
#define OPTS_HUMAN_READABLE	(1 << 5)
#define OPTS_ALLOC_WMARK	(1 << 6)

enum alloc_stats {
	STATS_MALLOC_SZ,
	STATS_MMAP_SZ,
	MAX_STATS
};

#define STATS_FREE	(MAX_STATS + 1)
#define STATS_MLOCK	(STATS_FREE + 1)
#define STATS_AUX	(STATS_MLOCK + 1)

struct options {
	FILE *fd;
	int flags;

	unsigned long stats[MAX_STATS];
};
#endif /* __OPTIONS_H */
