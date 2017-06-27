/*
 * Copyright (C) 2017 Sergey Senozhatsky
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef _PARSER_H
#define _PARSER_H

#include <sys/time.h>

#include <map>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <cstdlib>
#include <cstring>
#include <functional>

#include <event_names.h>

using namespace std;

struct options {
	std::string file;
	int plain;
	int debug;
};

struct backtrace {
	unsigned long addr;
	unsigned long offt;
	long num;
};

struct mm_event {
	enum events type;

	int tid;
	unsigned long addr;
	unsigned long size;

	unsigned long prev_addr;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offt;
	unsigned long mask;
	unsigned long ret;
	unsigned long align;

	unsigned long mem_from;
	unsigned long mem_to;

	struct timeval timestamp;

	size_t trace_hash;
	std::vector<struct backtrace> trace;
};

struct mem_area {
	unsigned long size;
	struct mm_event *event;
};

struct proc_tid {
	int tid;

	std::vector<struct mm_event *> events;
	unsigned long stats[EVENT_MAX];
};

struct formatter {
	const char *regex;
	int match_count;

	int (*parse)(struct mm_event *event, string &line);
};

int malloc_event_header(struct mm_event *event, string &line);
int free_event_header(struct mm_event *event, string &line);
int calloc_event_header(struct mm_event *event, string &line);
int cfree_event_header(struct mm_event *event, string &line);
int realloc_event_header(struct mm_event *event, string &line);
int memalign_event_header(struct mm_event *event, string &line);
int posix_memalign_event_header(struct mm_event *event, string &line);
int aligned_alloc_event_header(struct mm_event *event, string &line);
int valloc_event_header(struct mm_event *event, string &line);
int pvalloc_event_header(struct mm_event *event, string &line);
int mmap_event_header(struct mm_event *event, string &line);
int munmap_event_header(struct mm_event *event, string &line);
int mmap2_event_header(struct mm_event *event, string &line);
int memset_event_header(struct mm_event *event, string &line);
int memmove_event_header(struct mm_event *event, string &line);
int mlock_event_header(struct mm_event *event, string &line);
int munlock_event_header(struct mm_event *event, string &line);
int mlockall_event_header(struct mm_event *event, string &line);
int munlockall_event_header(struct mm_event *event, string &line);

static const formatter formatters[] = {
	// $ suffix
	// EVENT_MALLOC
	{
		"[t:%d][t:%lu.%lu] MA$(%lu)=0x%x",
		5,
		malloc_event_header,
	},
	// EVENT_CALLOC
	{
		"[t:%d][t:%lu.%lu] CA$(%lu, %lu)=0x%x",
		6,
		calloc_event_header,
	},
	// EVENT_REALLOC
	{
		"[t:%d][t:%lu.%lu] RE$(0x%x, %lu)=0x%x",
		6,
		realloc_event_header,
	},
	// EVENT_FREE
	{
		"[t:%d][t:%lu.%lu] FR$(0x%x)",
		4,
		free_event_header,
	},
	// EVENT_CFREE
	{
		"[t:%d][t:%lu.%lu] CF$(0x%x)",
		4,
		cfree_event_header,
	},
	// EVENT_MEMALIGN
	{
		"[t:%d][t:%lu.%lu] ME$(%lu, %lu)=0x%x",
		6,
		memalign_event_header,
	},
	// EVENT_POSIX_MEMALIGN
	{
		"[t:%d][t:%lu.%lu] PO$(%lu, %lu)=0x%x",
		6,
		posix_memalign_event_header,
	},
	// EVENT_ALIGNED_ALLOC
	{
		"[t:%d][t:%lu.%lu] AL$(%lu, %lu)=0x%x",
		6,
		aligned_alloc_event_header,
	},
	// EVENT_VALLOC
	{
		"[t:%d][t:%lu.%lu] VA$(%lu)=0x%x",
		5,
		valloc_event_header,
	},
	// EVENT_PVALLOC
	{
		"[t:%d][t:%lu.%lu] PV$(%lu)=0x%x",
		5,
		pvalloc_event_header,
	},

	// ! suffix
	// EVENT_MEMMOVE
	{
		"[t:%d][t:%lu.%lu] MM!(0x%x, 0x%x, %lu)=0x%x",
		7,
		memmove_event_header,
	},
	// EVENT_MEMSET
	{
		"[t:%d][t:%lu.%lu] MS!(0x%x, %d, %lu)=0x%x",
		7,
		memset_event_header,
	},

	// & suffix
	// EVENT_MMAP
	{
		"[t:%d][t:%lu.%lu] MM&(0x%x, %lu, %d, %d, %d, %lu)=0x%x",
		10,
		mmap_event_header,
	},
	// EVENT_MUNMAP
	{
		"[t:%d][t:%lu.%lu] MU&(0x%x, %lu)=%d",
		6,
		munmap_event_header,
	},
	// EVENT_MMAP2
	{
		"[t:%d][t:%lu.%lu] MM2&(0x%x, %lu, %d, %d, %d, %lu)=0x%x",
		10,
		mmap2_event_header,
	},

	// # suffix
	// EVENT_MLOCK
	{
		"[t:%d][t:%lu.%lu] ML#(0x%x, %lu)=%d",
		6,
		mlock_event_header,
	},
	// EVENT_MUNLOCK
	{
		"[t:%d][t:%lu.%lu] MU#(0x%x, %lu)=%d",
		6,
		munlock_event_header,
	},
	// EVENT_MLOCKALL
	{
		"[t:%d][t:%lu.%lu] MLA#(%d)=%d",
		5,
		mlockall_event_header,
	},
	// EVENT_MUNLOCKALL
	{
		"[t:%d][t:%lu.%lu] MUA#()=%d",
		4,
		munlockall_event_header,
	},
};

#endif /* _PARSER_H */
