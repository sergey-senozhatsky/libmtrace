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

#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <pthread.h>
#include <symbol_lookup.h>
#include <output.h>

static long max_idx = 0;
static long symbols_sz = 400;
static struct resovled_sym *symbols;
static unsigned long symbol_nr = 0;
static pthread_rwlock_t lock;

static void __init(void)
{
	if (!symbols)
		symbols = malloc(sizeof(struct resovled_sym) * symbols_sz);

	if (!symbols)
		abort();
}

static int sym_compare(const void *a, const void *b)
{
	const struct resovled_sym *sa = (const struct resovled_sym *) a;
	const struct resovled_sym *sb = (const struct resovled_sym *) b;

	if (sa->start_ip > sb->start_ip)
		return 1;
	if (sa->start_ip == sb->start_ip)
		return 0;
	if (sa->start_ip < sb->start_ip)
		return -1;
}

static long __lookup(unsigned long ip)
{
	long lo = 0;
	long hi = max_idx - 1;
	long mid;

	while (lo <= hi) {
		mid = lo + (hi - lo) / 2;

		if (symbols[mid].start_ip <= ip &&
				ip <= symbols[mid].end_ip)
			return mid;
		if (symbols[mid].start_ip > ip)
			hi = mid - 1;
		if (symbols[mid].start_ip < ip)
			lo = mid + 1;
	}

	return -1;
}

struct resovled_sym add_resolved_symbol(struct options *opts,
		unsigned long start_ip,
		unsigned long end_ip,
		char *fn_name)
{
	long idx;
	struct resovled_sym s = {0, 0, 0, UNRESOLVED_SYM_NAME};

	if (pthread_rwlock_wrlock(&lock) != 0)
		abort();

	__init();

	symbols[max_idx].start_ip = start_ip;
	symbols[max_idx].end_ip = end_ip;
	symbols[max_idx].nr = symbol_nr;

	if (fn_name == UNRESOLVED_SYM_NAME)
		symbols[max_idx].fn_name = UNRESOLVED_SYM_NAME;
	else
		symbols[max_idx].fn_name = strdup(fn_name);

	/* report a new resolved symbol and its seq nr */
	if (!(opts->flags & OPTS_HUMAN_READABLE)) {
		output("[f:%ld][%x-%x][%s]\n",
			symbol_nr, start_ip, end_ip, fn_name);
	}

	s = symbols[max_idx];
	symbol_nr++;
	max_idx++;

	if (max_idx >= symbols_sz - 1) {
		void *new_table;

		symbols_sz += symbols_sz / 2;
		new_table = realloc(symbols,
				symbols_sz * sizeof(struct resovled_sym));

		if (!new_table)
			abort();
		symbols = new_table;
	}

	qsort(symbols, max_idx - 1, sizeof(struct resovled_sym), sym_compare);
	pthread_rwlock_unlock(&lock);

	return s;
}

struct resovled_sym lookup_resolved_symbol(unsigned long ip)
{
	long idx;
	struct resovled_sym s = {0, 0, 0, UNRESOLVED_SYM_NAME};

	if (pthread_rwlock_rdlock(&lock) != 0)
		abort();

	idx = __lookup(ip);
	if (idx != -1)
		s = symbols[idx];

	pthread_rwlock_unlock(&lock);

	return s;
}

/*
 * This is early init. Do not allocate dynamic buffers here, since
 * we are still in __init mode.
 */
void early_lookup_init(void)
{
	if (pthread_rwlock_init(&lock, NULL) != 0)
		abort();
}
