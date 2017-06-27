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

#include <sys/ioctl.h>
#include <sys/types.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <cstring>
#include <fstream>
#include <sys/mman.h>
#include <unordered_map>

using namespace std;

#include "parser.h"

#define ALIGN(x, a)     (((x) + (a) - 1) & ~((a) - 1))

static struct options opts = {
	.file = string(),
	.plain = 0,
	.debug = 0,
};

static map<int, struct proc_tid*> proc_map;

static unordered_map<size_t, long> callpath_freq;

struct symbol {
	long nr;
	unsigned long start_ip;
	unsigned long end_ip;
	string name;
};

static vector<struct mm_event *> mm_event_top;

static vector<struct symbol> symbols;
static std::map<unsigned long, struct mem_area *> mem_area;

static int security_report = 0;

#define MAX_EVENTS_IN_TOP_LIST	100UL

#define MAX_MEM_CELLS_IN_A_ROW	68

#define CELL_COLOR_USED_MMAP	"#4dffb8"
#define CELL_COLOR_USED_ALLOC	"#aaff80"
#define CELL_COLOR_USED_MEMSET	"#b3ffb3"
#define CELL_COLOR_UNUSED	"#e6f7ff"

#define CELL_COLOR_WARNING	"#ffcccc"

#define CELL_BORDER_COLOR_BACKTRACE	"has_backtrace"
#define CELL_BORDER_COLOR_NO_BACKTRACE	"has_no_backtrace"

#define CELL_BORDER_COLOR_MLOCKED	"mlocked"

static bool events_sz_cmp(const struct mm_event *a, const struct mm_event *b)
{
	unsigned long sz1 = a->size;
	unsigned long sz2 = b->size;

	if (a->type == EVENT_CALLOC)
		sz1 *= a->flags;

	if (b->type == EVENT_CALLOC)
		sz2 *= b->flags;

	if (a->type == EVENT_MEMALIGN ||
			a->type == EVENT_POSIX_MEMALIGN ||
			a->type == EVENT_ALIGNED_ALLOC)
		sz1 = ALIGN(sz1, a->align);

	if (b->type == EVENT_MEMALIGN ||
			b->type == EVENT_POSIX_MEMALIGN ||
			b->type == EVENT_ALIGNED_ALLOC)
		sz2 = ALIGN(sz2, b->align);

	if (sz1 == sz2) {
		if (a->timestamp.tv_sec == b->timestamp.tv_sec)
			return a->timestamp.tv_usec > b->timestamp.tv_usec;
		return a->timestamp.tv_sec > b->timestamp.tv_sec;
	}

	return sz1 < sz2;
}

static void event_add_trace(struct mm_event *event, struct backtrace &trace)
{
	event->trace.push_back(trace);
}

int malloc_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_MALLOC;
	return sscanf(line.c_str(), formatters[EVENT_MALLOC].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->size,
				&event->addr);
}

int free_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_FREE;
	return sscanf(line.c_str(), formatters[EVENT_FREE].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->addr);
}

int calloc_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_CALLOC;
	return sscanf(line.c_str(), formatters[EVENT_CALLOC].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->size,
				&event->flags,
				&event->addr);
}

int cfree_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_CFREE;
	return sscanf(line.c_str(), formatters[EVENT_CFREE].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->addr);
}

int realloc_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_REALLOC;
	return sscanf(line.c_str(), formatters[EVENT_REALLOC].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->prev_addr,
				&event->size,
				&event->addr);
}

int memalign_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_MEMALIGN;
	return sscanf(line.c_str(), formatters[EVENT_MEMALIGN].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->size,
				&event->align,
				&event->addr);
}

int posix_memalign_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_POSIX_MEMALIGN;
	return sscanf(line.c_str(), formatters[EVENT_POSIX_MEMALIGN].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->size,
				&event->align,
				&event->addr);
}

int aligned_alloc_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_ALIGNED_ALLOC;
	return sscanf(line.c_str(), formatters[EVENT_ALIGNED_ALLOC].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->size,
				&event->align,
				&event->addr);
}

int valloc_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_VALLOC;
	return sscanf(line.c_str(), formatters[EVENT_VALLOC].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->size,
				&event->addr);
}

int pvalloc_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_PVALLOC;
	return sscanf(line.c_str(), formatters[EVENT_PVALLOC].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->size,
				&event->addr);
}

int mmap_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_MMAP;
	return sscanf(line.c_str(), formatters[EVENT_MMAP].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->prev_addr,
				&event->size,
				&event->prot,
				&event->flags,
				&event->fd,
				&event->offt,
				&event->addr);
}

int munmap_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_MUNMAP;
	return sscanf(line.c_str(), formatters[EVENT_MUNMAP].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->addr,
				&event->size,
				&event->ret);
}

int mmap2_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_MMAP2;
	return sscanf(line.c_str(), formatters[EVENT_MMAP2].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->prev_addr,
				&event->size,
				&event->prot,
				&event->flags,
				&event->fd,
				&event->offt,
				&event->addr);
}

int memset_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_MEMSET;
	return sscanf(line.c_str(), formatters[EVENT_MEMSET].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->addr,
				&event->mask,
				&event->size,
				&event->prev_addr);
}

int memmove_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_MEMMOVE;
	return sscanf(line.c_str(), formatters[EVENT_MEMMOVE].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->addr,
				&event->prev_addr,
				&event->size,
				&event->addr);
}

int mlock_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_MLOCK;
	return sscanf(line.c_str(), formatters[EVENT_MLOCK].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->addr,
				&event->size,
				&event->ret);
}

int munlock_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_MUNLOCK;
	return sscanf(line.c_str(), formatters[EVENT_MUNLOCK].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->addr,
				&event->size,
				&event->ret);
}

int mlockall_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_MLOCKALL;
	return sscanf(line.c_str(), formatters[EVENT_MLOCKALL].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->flags,
				&event->ret);
}

int munlockall_event_header(struct mm_event *event, string &line)
{
	event->type = EVENT_MUNLOCKALL;
	return sscanf(line.c_str(), formatters[EVENT_MUNLOCKALL].regex,
				&event->tid,
				&event->timestamp.tv_sec,
				&event->timestamp.tv_usec,
				&event->ret);
}

static struct mm_event *new_mm_event(string &line)
{
	int i = 0;

	while (i < EVENT_MAX) {
		int ret = 0;

		if (line.find(event_names[i].compact_name) != string::npos) {
			struct mm_event *event = new struct mm_event;

			event->mem_from = 0;
			event->mem_to = 0;
			event->trace_hash = 0;

			ret = formatters[i].parse(event, line);
			if (ret != formatters[event->type].match_count) {
				cerr << "Error parsing: " << line << endl;
				delete event;
				return NULL;
			}

			return event;
		}

		i++;
	}

	return NULL;
}

static void append_symbol(string &line)
{
	long nr;
	unsigned long start_ip, end_ip;

	// [f:5][42d91d68-42d91dd7][log_config_push]
	if (sscanf(line.c_str(),
			"[f:%ld][%lx-%lx]",
			&nr, &start_ip, &end_ip) != 3) {
		cerr << "Can't decode symbol: " << line << endl;
		return;
	}

	size_t pos = 0;
	int i = 0;
	while (i < 3) {
		pos = line.find_first_of('[', pos);
		pos++;
		i++;
	}

	if (pos == string::npos) {
		cerr << "Can't decode symbol: " << line << endl;
		return;
	}

	if (nr + 1 >= symbols.size())
		symbols.resize(nr + 1);

	symbols[nr].nr = nr;
	symbols[nr].start_ip = start_ip;
	symbols[nr].end_ip = end_ip;
	symbols[nr].name = line.substr(pos, line.size() - pos - 1);
}

static void string_chomp(string &line)
{
	int c;

	for (int i = line.size() - 1; i >= 0; i--) {
		if (line[i] == '\r' || line[i] == '\n') {
			line[i] = ' ';
			c++;
			if (c > 1)
				break;
		}
	}
}

static int parse_event_backtrace(struct mm_event *event, string &line)
{
	struct backtrace trace;
	
	//#42d91d8b#5#23
	if (sscanf(line.c_str(), "#%lx#%ld#%lx",
			&trace.addr,
			&trace.num,
			&trace.offt) != 3) {
		cerr << "Can't parse backtrace: " << line << endl;
		return -1;
	}

	event->trace.push_back(trace);
	return 0;
}

static struct proc_tid *get_proc_tid(int tid)
{
	struct proc_tid *proc;
	
	if (proc_map.find(tid) == proc_map.end()) {
		proc = new proc_tid;

		proc->tid = tid;
		memset(proc->stats, 0x00, sizeof(proc->stats));
		proc_map[tid] = proc;
	} else {
		proc = proc_map[tid];
	}

	return proc;
}

static void __print_event(struct mm_event *event);

static void add_tid_event(struct mm_event *event)
{
	struct proc_tid *proc = get_proc_tid(event->tid);

	if (event->trace.size() != 0) {
		size_t _hash = 0;

		for (auto &p : event->trace) {
			size_t fh = std::hash<size_t>{}(p.addr);
			_hash ^= (fh << 1);
			_hash = std::hash<size_t>{}(_hash);
		}

		if (_hash != 0) {
			if (callpath_freq.find(_hash) != callpath_freq.end())
				callpath_freq[_hash]++;
			else
				callpath_freq[_hash] = 1;
		}
		event->trace_hash = _hash;
	}

	proc->events.push_back(event);
	proc->stats[event->type]++;
}

static void add_mem_area(struct mm_event *event)
{
	unsigned long size = 0;
	unsigned long addr = 0;

	/* MEMSET can be called on a sub-range of allocated object.
	 * e.g. allocate structure, memset() a small buffer in
	 * that structure. It will require a whole linear scan of
	 * the tree to find the proper sub-object.
	 *
	 * so skip MEMSET events for now.
	 */
	if (event->type == EVENT_MEMSET)
		return;

	if (event->type == EVENT_REALLOC) {
		if (mem_area.find(event->prev_addr) != mem_area.end()) {
			delete mem_area[event->prev_addr];
			mem_area.erase(event->prev_addr);
		}
	}

	if (event->type == EVENT_MALLOC ||
		event->type == EVENT_REALLOC ||
		event->type == EVENT_MMAP ||
		event->type == EVENT_MMAP2 ||
		event->type == EVENT_CALLOC ||
		event->type == EVENT_MEMALIGN ||
		event->type == EVENT_POSIX_MEMALIGN ||
		event->type == EVENT_ALIGNED_ALLOC ||
		event->type == EVENT_VALLOC ||
		event->type == EVENT_PVALLOC ||
		event->type == EVENT_MEMSET) {

		size = event->size;
		addr = event->addr;
	}

	if (event->type == EVENT_CALLOC)
		size *= event->flags;

	if (event->type == EVENT_MEMALIGN ||
			event->type == EVENT_POSIX_MEMALIGN ||
			event->type == EVENT_ALIGNED_ALLOC)
		size = ALIGN(size, event->align);

	if (!addr && !size)
		return;

	if (mem_area.find(addr) != mem_area.end()) {
		return;

		if (mem_area[addr]->event->trace.size() != 0)
			return;
		if (event->trace.size() == 0)
			return;
		delete mem_area[addr];
	}

	struct mem_area *mem = new struct mem_area;
	mem->size = size;
	mem->event = event;

	mem_area[addr] = mem;
}

static void remove_mem_area(struct mm_event *event)
{
	if (!(event->type == EVENT_FREE ||
		event->type == EVENT_CFREE ||
		event->type == EVENT_MUNMAP))
			return;

	if (mem_area.find(event->addr) != mem_area.end()) {
		delete mem_area[event->addr];
		mem_area.erase(event->addr);
	}
}

static int parse_file(struct options *opts)
{
	struct mm_event *event = NULL;
	int ret = 0;

	ifstream log_file;
	string line;

	log_file.open(opts->file.c_str());
	if (!log_file.is_open())
		return -EINVAL;

	while (getline(log_file, line)) {
		string_chomp(line);

		if (line.find("[t:") != std::string::npos) {
			// commit already existing event
			if (event) {
				add_tid_event(event);
				add_mem_area(event);
				remove_mem_area(event);
			}

			event = new_mm_event(line);
			if (!event) {
				cerr << "Can't parse event header: " <<
					line << endl;
				return -1;
			}
			continue;
		}

		if (line.find("[f:") != string::npos) {
			append_symbol(line);
			continue;
		}

		if (line.find("[m:") != string::npos) {
			// [m:86274048-86278144]
			if (sscanf(line.c_str(), "[m:%ld-%ld]",
						&event->mem_from,
						&event->mem_to) != 2) {
				cerr << "Can't parse mm: " << line << endl;
			}
			continue;
		}

		if (line[0] == '#') {
			parse_event_backtrace(event, line);
			continue;
		}

		if (line[0] == '-') {
			cerr << "Error: " << line << endl;
			continue;
		}
	}

	if (opts->debug)
		cout << "File parsed" << endl;

out:
	log_file.close();
	return ret;
}

static void decode_mmap_prot(int prot)
{
	if (prot & PROT_EXEC && prot & PROT_WRITE)
		security_report = 1;

	printf("%d /* <b>", prot);

	if (prot & PROT_EXEC)
		printf("PROT_EXEC ");
	if (prot & PROT_READ)
		printf("PROT_READ ");
	if (prot & PROT_WRITE)
		printf("PROT_WRITE ");
	if (prot & PROT_NONE)
		printf("PROT_NONE ");

	printf("</b>*/, ");
}

static void decode_mmap_flags(int flags)
{
	printf("%d /* <b>", flags);

	if (flags & MAP_SHARED)
		printf("MAP_SHARED ");
	if (flags & MAP_PRIVATE)
		printf("MAP_PRIVATE ");
	if (flags & MAP_32BIT)
		printf("MAP_32BIT ");
	if (flags & MAP_ANON)
		printf("MAP_ANON ");
	if (flags & MAP_ANONYMOUS)
		printf("MAP_ANONYMOUS ");
	if (flags & MAP_DENYWRITE)
		printf("MAP_DENYWRITE ");
	if (flags & MAP_EXECUTABLE)
		printf("MAP_EXECUTABLE ");
	if (flags & MAP_FILE)
		printf("MAP_FILE ");
	if (flags & MAP_FIXED)
		printf("MAP_FIXED ");
	if (flags & MAP_GROWSDOWN)
		printf("MAP_GROWSDOWN ");
	if (flags & MAP_HUGETLB)
		printf("MAP_HUGETLB ");
	if (flags & MAP_LOCKED)
		printf("MAP_LOCKED ");
	if (flags & MAP_NONBLOCK)
		printf("MAP_NONBLOCK ");
	if (flags & MAP_NORESERVE)
		printf("MAP_NORESERVE ");
	if (flags & MAP_POPULATE)
		printf("MAP_POPULATE ");
	if (flags & MAP_STACK)
		printf("MAP_STACK ");

	printf("</b>*/, ");
}

static void print_event_header(struct mm_event *event)
{
	if (!event)
		return;

	printf("[%lu.%06d] Thread %d \n <br><br>",
			event->timestamp.tv_sec,
			event->timestamp.tv_usec,
			event->tid);

	printf("Issued <b>%s</b>(", event_names[event->type]);

	if (event->type == EVENT_MALLOC ||
			event->type == EVENT_VALLOC ||
			event->type == EVENT_PVALLOC) {
		printf("%ld) = 0x%x",
				event->size,
				event->addr);
	}

	if (event->type == EVENT_MEMALIGN ||
			event->type == EVENT_POSIX_MEMALIGN ||
			event->type == EVENT_ALIGNED_ALLOC) {
		printf("%ld, %ld) = 0x%x",
				event->size,
				event->align,
				event->addr);
	}

	if (event->type == EVENT_CALLOC) {
		printf("%ld, %ld) = 0x%x",
				event->size,
				event->flags,
				event->addr);
	}

	if (event->type == EVENT_FREE || event->type == EVENT_CFREE) {
		printf("0x%x)\n<br>", event->addr);
	}

	if (event->type == EVENT_REALLOC) {
		printf("0x%x, %ld) = 0x%x",
				event->prev_addr,
				event->size,
				event->addr);
	}

	if (event->type == EVENT_MMAP || event->type == EVENT_MMAP2) {
		printf("0x%x, %ld, ", event->prev_addr, event->size);
		decode_mmap_prot(event->prot);
		decode_mmap_flags(event->flags);
		printf("%d, %ld) = 0x%x",
				event->fd,
				event->offt,
				event->addr);
	}

	if (event->type == EVENT_MUNMAP) {
		printf("0x%x, %lx) = %d",
				event->addr,
				event->size,
				event->ret);
	}

	if (event->type == EVENT_MEMSET) {
		printf("0x%x, ", event->addr);

		if (event->mask == 0x00)
			printf("'0'");
		else
			printf("'%c'", event->mask);

		printf(", %ld) = 0x%x",
				event->size,
				event->prev_addr);
	}

	if (event->type == EVENT_MEMMOVE) {
		printf("0x%x, 0x%x, %ld) = 0x%x",
				event->addr,
				event->prev_addr,
				event->size,
				event->addr);
	}

	if (event->type == EVENT_MLOCK || event->type == EVENT_MUNLOCK) {
		printf("0x%x, %ld) = %ld",
				event->addr,
				event->size,
				event->ret);
	}

	if (event->type == EVENT_MLOCKALL) {
		printf("%ld) = %ld",
				event->flags,
				event->ret);
	}

	if (event->type == EVENT_MUNLOCKALL) {
		printf(") = %ld",
				event->ret);
	}

	printf("\n<br><br>");
}

static void print_mem_growth(struct mm_event *event)
{
	if (!event)
		return;

	if (event->mem_from != event->mem_to) {
		printf("Detected /proc/self/statm <b>RSS</b> change from %lu to %lu bytes\n<br>",
				event->mem_from,
				event->mem_to);

		printf("/* Diff: %ld\n */\n<br><br>",
				event->mem_to - event->mem_from);
	}
}

static long num_cells = 0;
static int cells = 0;

static void __print_event(struct mm_event *event)
{
	print_event_header(event);
	print_mem_growth(event);

	if (!event) {
		printf("&nbsp; <br>\n");
		return;
	}

	if (event->trace.size() != 0) {
		auto tr = event->trace.begin();

		printf(" Backtrace: \n <br> ");

		while (tr != event->trace.end()) {
			printf("&nbsp; [<0x%08lx>] %s+0x%lx &nbsp; \n <br>",
					tr->addr,
					symbols[tr->num].name.c_str(),
					tr->offt);
			tr++;
		}
	} else {
		printf(" No backtrace available \n <br> ");
	}
}

static int ignore_event_type(int eid)
{
	if (eid == EVENT_FREE ||
		eid == EVENT_CFREE ||
		eid == EVENT_MEMMOVE ||
		eid == EVENT_MUNMAP ||
		eid == EVENT_MEMSET ||
		eid == EVENT_MLOCK ||
		eid == EVENT_MLOCKALL ||
		eid == EVENT_MUNLOCK ||
		eid == EVENT_MUNLOCKALL)
		return 1;

	return 0;
}

static void add_event_to_top_list(struct mm_event *event)
{
	if (!event)
		return;

	if (ignore_event_type(event->type))
		return;

	mm_event_top.push_back(event);
}

static void add_cell(const char *bgcolor, struct mm_event *event)
{
	const char *border_color = CELL_BORDER_COLOR_NO_BACKTRACE;

	if (event && event->trace.size() != 0)
		border_color = CELL_BORDER_COLOR_BACKTRACE;

	if (event && (event->type == EVENT_MLOCK ||
				event->type == EVENT_MLOCKALL))
		border_color = CELL_BORDER_COLOR_MLOCKED;

	printf("<td width=7 height=7 bgcolor=\"%s\" id=\"%s\" "
		"onclick='show_backtrace(\"backtrace%ld\");'>\n",
		bgcolor,
		border_color,
		num_cells);

	add_event_to_top_list(event);

	printf("<div id=\"backtrace%ld\" style=\"display: none\">", num_cells);

	__print_event(event);

	printf("</div>\n");
	printf("</td>\n");

	num_cells++;
	cells++;
	if (cells >= MAX_MEM_CELLS_IN_A_ROW) {
		printf("</tr>\n");
		printf("<tr>\n");
		cells = 0;
	}
}

static void do_security_report(void)
{
	auto p = mem_area.begin();

	printf("<table width=50%>\n");
	printf("<tr width=50%><td>\n");
	printf("<tr><td bgcolor=\"%s\">\n",
		CELL_COLOR_WARNING);
	printf("<a name=\"security_report\"></a>Go to list "
		"<a style=\"text-decoration: none; color: #7191bc;\" href=\"#list_top\"><b>top</b></a>\n<br>\n");
	printf("<br><b>Security report</b><br>");
	printf("</td></tr>\n");

	while (p != mem_area.end()) {
		if (p->second->event->type != EVENT_MMAP &&
				p->second->event->type != EVENT_MMAP2)
			goto skip;

		if ((p->second->event->prot & PROT_EXEC) &&
				(p->second->event->prot & PROT_WRITE)) {
			printf("<tr><td>\n");
			__print_event(p->second->event);
			printf("</td></tr>\n");

			printf("<tr><td bgcolor=\"%s\">\n",
					CELL_COLOR_UNUSED);
			printf("<br></td></tr>\n");
		}
skip:
		p++;
	}

	printf("</table>\n");
}

static void do_event_top_report(void)
{
	printf("<a name=\"list_top\"></a>\n");

	printf("<table width=50%>\n");
	printf("<tr width=50%><td>\n");
	printf("Per-event type top list sorted by size in reverse order. (Up to %ld events of each type)\n<br>\n",
			MAX_EVENTS_IN_TOP_LIST);
	printf("</td></tr>\n");

	printf("<tr><td>\n");
	printf("<table><tr>\n");
	for (int eid = 0; eid < EVENT_MAX; eid++) {
		if (ignore_event_type(eid))
			continue;
		printf("<td>&nbsp; <a style=\"text-decoration: none; color: #7191bc;\" href=\"#list_%d\"> <b>%s</b> </a>  &nbsp;</td>\n",
				eid, event_names[eid].human_name);
	}
	printf("</tr></table><br>\n");
	printf("</td></tr>\n");

	std::sort(mm_event_top.begin(), mm_event_top.end(), events_sz_cmp);

	for (int eid = 0; eid < EVENT_MAX; eid++) {
		int top_list = 0;
		auto rb = mm_event_top.rbegin();

		if (ignore_event_type(eid))
			continue;

		printf("<tr><td bgcolor=\"%s\">\n",
			CELL_COLOR_USED_MEMSET);
		printf("<a name=\"list_%d\"></a>Go to list "
				"<a style=\"text-decoration: none; color: #7191bc;\" href=\"#list_top\"><b>top</b></a>\n<br>\n",
				eid);
		printf("<br>Event type: <b>%s</b><br>", event_names[eid]);
		printf("</td></tr>\n");

		while (top_list < MAX_EVENTS_IN_TOP_LIST && rb != mm_event_top.rend()) {
			struct mm_event *event = *rb;
	
			if (event->type == eid) {
				if (event->trace_hash != 0) {
					long num = callpath_freq[event->trace_hash];
					printf("<tr><td>\n");
					printf("This callpath has been seen %ld time%c [backtrace hash %llx]\n",
							num, num > 1 ? 's' : ' ',
							event->trace_hash);
					printf("</td></tr>\n");
				}
				printf("<tr><td>\n");
				__print_event(event);
				printf("</td></tr>\n");

				printf("<tr><td bgcolor=\"%s\">\n",
						CELL_COLOR_UNUSED);
				printf("<br></td></tr>\n");

				top_list++;
			}

			rb++;
		}
	}

	printf("</table>\n");
}

static void do_mem_area_report(void)
{
	auto p = mem_area.begin();
	unsigned long prev_end = 0;

	printf("<table width=100%>\n");
	printf("<tr>\n");

	printf("<td width=50%>\n");
	printf("Process memory snapshot (brief reconstruction)\n");
	printf("</td>\n");

	printf("<td>\n");
	printf("</td>\n");

	printf("</tr>\n");

	printf("<tr>\n");
	printf("<td width=50%>\n");

	printf("<table id=\"mem_area\">\n");
	printf("<tr>\n");

	while (p != mem_area.end()) {
		long sz;

		sz = p->first - prev_end;
		/* We can't show every single page from the range...
		 * down scale. */
		sz = min(5L, (long)sz / 4096 > 1 ? (long)sz / 4096 : 0);
		while (sz > 0) {
			add_cell(CELL_COLOR_UNUSED, NULL);
			sz--;
		}

		sz = p->second->size;
		if (sz == 0)
			goto next;

		/* down scale mem_area size to 1 cell per mem_area */
		sz = min(1L, (long)sz / 4096 ?: 1);
		while (sz > 0) {
			if (p->second->event->type == EVENT_MMAP ||
					p->second->event->type == EVENT_MMAP2)
				add_cell(CELL_COLOR_USED_MMAP, p->second->event);
			else if (p->second->event->type == EVENT_MEMSET)
				add_cell(CELL_COLOR_USED_MEMSET, p->second->event);
			else
				add_cell(CELL_COLOR_USED_ALLOC, p->second->event);
			sz--;
		}

next:
		prev_end = (p->first + p->second->size);
		p++;
	}

	printf("</tr>\n");
	printf("</table>\n");
}

static void generate_report(void)
{
	printf("<html>\n");

	printf("<head>\n");
	printf("<style>"
		"font-family: Arial,Helvetica Neue,Helvetica,sans-serif; \n"
		"font-size:11;\n"

		"table {\n"
		"	border: 1;\n"
		"	font-family: Arial,Helvetica Neue,Helvetica,sans-serif;\n"
		"	font-size:11px;\n"
		"	border-collapse: collapse;\n"
		"}\n"

		"th, tr, td {\n"
		"	border: 1px solid white;\n"
		"	font-family: Arial,Helvetica Neue,Helvetica,sans-serif;\n"
		"	font-size:11px;\n"
		"}\n"

		"td#has_backtrace {\n"
		"	border: 1px solid #ffa9a3;\n"
		"}\n"

		"td#has_no_backtrace {\n"
		"	border: 1px solid #e0e0e0;\n"
		"}\n"

		"td#mlocked {\n"
		"	border: 1px solid #b7fffb;\n"
		"}\n"

		"div#info_backtrace{\n"
		"	font-family: Arial,Helvetica Neue,Helvetica,sans-serif;\n"
		"	font-size:11px;\n"
		"	padding:2px;\n"
		"	position:fixed;\n"
		"	top:40px;\n"
		"}\n"
		"</style>\n"
	);

	printf("<script type=\"text/javascript\">\n"
	"function show_backtrace(id)\n"
	"{\n"
	"	var trace = document.getElementById(id).innerHTML;\n"
	"	document.getElementById(\"info_backtrace\").innerHTML = trace;\n"
	"}\n"
	"</script>\n"
	);

	printf("</head>\n");
	printf("<body>\n");
	printf("<table>");
	printf("<tr>\n");
	printf("<td width=5 height=5 bgcolor=\"%s\" id=\"%s\"> </td>\n",
			CELL_COLOR_UNUSED, CELL_BORDER_COLOR_NO_BACKTRACE);
	printf("<td>Free memory</td>\n");

	printf("<td width=5 height=5 bgcolor=\"%s\"> </td>\n",
			CELL_COLOR_USED_ALLOC);
	printf("<td>Allocated memory</td>\n");

	printf("<td width=5 height=5 bgcolor=\"%s\" id=\"%s\"> </td>\n",
			CELL_COLOR_USED_ALLOC, CELL_BORDER_COLOR_BACKTRACE);
	printf("<td>Event Backtrace has been captured</td>\n");

	printf("<td width=5 height=5 bgcolor=\"%s\"> </td>\n",
			CELL_COLOR_USED_MMAP);
	printf("<td>mmap-ed memory</td>\n");
	printf("</tr>\n");
	printf("</table>");

	printf("<br><br>\n");

	do_mem_area_report();

	printf("</td>\n");

	printf("<td>\n");
	printf("<div width=100 height=100 id=\"info_backtrace\"></div>\n");
	printf("</td>\n");
	printf("</tr>\n");

	printf("</table>\n");

	printf("<br><br><br><br>\n");

	if (security_report) {
		printf("<table width=50%>\n");
		printf("<tr width=50%><td bgcolor=\"%s\">\n",
				CELL_COLOR_WARNING);
		printf("Potential security problems [please review]\n<br>");
		printf("We have discovered mappings that are both WRITE-able and EXEC-utable: ");
		printf("<a style=\"text-decoration: none; color: #7191bc;\" href=\"#%s\"><b>%s</b></a>\n",
				"security_report", "security report");
		printf("<tr><td>\n");
		printf("</table>\n");
	}

	do_event_top_report();

	if (security_report)
		do_security_report();

	printf("</body>\n");
	printf("</html>\n");
}

static void error_usage(void)
{
	printf("parser\n"
		"-f --file=FILE      MM mode file to parse\n"
		"-p                  plain output (do not demangle C++ names)\n"
		"-d                  debug mode\n");
	exit(1);
}

int main(int argc, char **argv)
{
	static struct option long_options[] = {
		{"file", 1, 0, 'f'},
		{"plain", 0, 0, 'p'},
		{"debug", 0, 0, 'd'},
		{0, 0, 0, 0}
	};

	const char *appopts = "f:pd";
	while (1) {
		int c = getopt(argc, argv, appopts);
		if (c == -1)
			break;

		switch (c) {
			case 'f':
				opts.file = optarg;
				break;
			case 'p':
				opts.plain = 1;
				break;
			case 'd':
				opts.debug = 1;
				break;
			default:
				error_usage();
		}
	}

	if (opts.file.empty())
		error_usage();

	if (!opts.plain) {
		char command[4096];

		sprintf(command, "cat %s | c++filt > %s.demangled",
				opts.file.c_str(), opts.file.c_str());
		if (system(command) != 0)
			return -EINVAL;

		opts.file += ".demangled";
	}

	if (parse_file(&opts)) {
		cerr << "Can't parse the file" << endl;
		unlink(opts.file.c_str());
		return -EINVAL;
	}

	generate_report();

	return EXIT_SUCCESS;
}
