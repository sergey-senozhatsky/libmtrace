#ifndef _EVENT_NAMES_H_
#define _EVENT_NAMES_H_

struct event_name {
	const char *human_name;
	const char *compact_name;
};

static struct event_name event_names[] = {
	{
		"malloc",
		"MA$",
	},

	{
		"calloc",
		"CA$",
	},

	{
		"realloc",
		"RE$",
	},

	{
		"free",
		"FR$",
	},

	{
		"cfree",
		"CF$",
	},

	{
		"memalign",
		"ME$",
	},

	{
		"posix_memalign",
		"PO$",
	},

	{
		"aligned_alloc",
		"AL$",
	},

	{
		"valloc",
		"VA$",
	},

	{
		"pvalloc",
		"PV$",
	},

	{
		"memmove",
		"MM!",
	},

	{
		"memset",
		"MS!",
	},

	{
		"mmap",
		"MM&",
	},

	{
		"munmap",
		"MU&",
	},

	{
		"mmap2",
		"MM2&",
	},

	{
		"mlock",
		"ML#",
	},

	{
		"munlock",
		"MU#",
	},

	{
		"mlockall",
		"MLA#",
	},

	{
		"munlockall",
		"MUA#",
	}
};

enum events {
	EVENT_MALLOC,
	EVENT_CALLOC,
	EVENT_REALLOC,
	EVENT_FREE,
	EVENT_CFREE,
	EVENT_MEMALIGN,
	EVENT_POSIX_MEMALIGN,
	EVENT_ALIGNED_ALLOC,
	EVENT_VALLOC,
	EVENT_PVALLOC,
	EVENT_MEMMOVE,
	EVENT_MEMSET,
	EVENT_MMAP,
	EVENT_MUNMAP,
	EVENT_MMAP2,
	EVENT_MLOCK,
	EVENT_MUNLOCK,
	EVENT_MLOCKALL,
	EVENT_MUNLOCKALL,
	EVENT_MAX
};

#endif /* _EVENT_NAMES_H_ */
