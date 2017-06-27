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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef UNW_LOCAL_ONLY
#define UNW_LOCAL_ONLY
#endif
#include <libunwind.h>

#include "config.h"
#include <output.h>
#include <unwind_trace.h>
#include <symbol_lookup.h>
#include <maps_cache.h>

static int skip_frames = 2;
static int unwind_depth = UNWIND_DEPTH;

static volatile __thread int recursion;

static int output_frame(struct options *opts,
			unw_word_t ip,
			struct resovled_sym *sym)
{
	unsigned long offset = ip - sym->start_ip;

	if (opts->flags & OPTS_HUMAN_READABLE)
		output("# [<0x%x>] %s+0x%x\n",
				ip, sym->fn_name, offset);
	else
		output("#%x#%ld#%x\n",
				ip, sym->nr, offset);

	return sym->fn_name == UNRESOLVED_SYM_NAME;
}

void unwind_set_depth(int __depth)
{
	unwind_depth = __depth;
}

void unwind_trace(struct options *opts)
{
	static __thread char fn_name[MAX_FN_NAME_BUF_SZ] = {0,};
	int depth = unwind_depth;
	unw_cursor_t cursor; unw_context_t uc;
	int frame_nr = 0;

	if (recursion) {
		output("-unwind recursion\n");
		return;
	}
	recursion++;

	if (unw_getcontext(&uc) != 0) {
		output("-unwind context init error");
		recursion--;
		return;
	}

	if (unw_init_local(&cursor, &uc) != 0) {
		output("-unwind local init error");
		recursion--;
		return;
	}

	while (depth) {
		unw_word_t ip;
		unsigned long offset;
		int should_break = 0;
		unw_proc_info_t pip;
		struct resovled_sym symbol;

		int rc = unw_get_reg(&cursor, UNW_REG_IP, &ip);
		if (rc != 0)
			break;

		/*
		 * Check if IP belongs to a PROT_EXEC mapping.
		 */
		if (maps_cache_lookup(ip) != 0)
			break;

		frame_nr++;
		/* first two frames are always us - event->unwind_trace()*/
		if (frame_nr <= skip_frames)
			goto cont;

		/*
		 * unw_get_proc_name() is really-really-really slow. because
		 * for every IP resolution it opens a ELF file, parses it's
		 * symtabs, then lookups for the symbol.
		 *
		 * what we do here is a lazy hashing. we don't read/parse/store
		 * all symbols from every ELF that process has opened. instead
		 * we keep only symbols that were resolved during previous stack
		 * unwind operations - backtraces quite often contain similar
		 * frames.
		 */
		symbol = lookup_resolved_symbol(ip);
		if (symbol.start_ip != 0) {
			should_break = output_frame(opts, ip, &symbol);
			goto cont;
		}

		rc = unw_get_proc_name(&cursor, fn_name,
				sizeof(fn_name),
				(unw_word_t *) &offset);
		if (rc == 0) {
			if (unw_get_proc_info(&cursor, &pip) != 0)
				break;

			symbol = add_resolved_symbol(opts,
						pip.start_ip,
						pip.end_ip,
						fn_name);
		} else {
			add_resolved_symbol(opts, ip, ip, UNRESOLVED_SYM_NAME);
		}

		should_break = output_frame(opts, ip, &symbol);

cont:
		if (should_break)
			break;
		if (unw_step(&cursor) <= 0)
			break;
		depth--;
	}

	recursion--;
}

void unwind_flush_cache(void)
{
	unw_flush_cache(unw_local_addr_space, 0, 0);
}
