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

#include <unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <limits.h>

#include "config.h"
#include <maps_cache.h>

static pthread_rwlock_t lock;

struct mmap_entry {
	unsigned long low;
	unsigned long high;
};

static int mmap_cache_sz = 400;
static struct mmap_entry *mmap_cache;
static int mmap_cache_max_id = 0;

static int deferred_flush;

static char *maps_buffer;

static int maps_add_entry(char *line)
{
	char r, w, x, p;

	/* LOW-HIGH PERM OFFSET MAJOR:MINOR INUM PATH */
	int ret = sscanf(line, "%lx-%lx %c%c%c%c",
			&mmap_cache[mmap_cache_max_id].low,
			&mmap_cache[mmap_cache_max_id].high,
			&r, &w, &x, &p);

	if (ret != 6) {
		fprintf(stderr, "maps buffer corruption: %s\n", line);
		abort();
		return -1;
	}

	if (x != 'x')
		return -1;

	mmap_cache_max_id++;
	if (mmap_cache_max_id >= mmap_cache_sz - 1) {
		void *new_buf;

		mmap_cache_sz += mmap_cache_sz / 2;
		new_buf = realloc(mmap_cache,
				mmap_cache_sz * sizeof(struct mmap_entry));
		if (!new_buf)
			abort();
		mmap_cache = new_buf;
	}
	return 0;
}

static int find_new_line_offt(char *mbuf, int sz)
{
	int i = 0;
	while (i < sz) {
		i++;
		if (mbuf[i] == 0x00)
			return -1;
		if (mbuf[i] == '\n')
			return i;
	}
	return -1;
}

static int process_maps_buffer(char *mbuf, int sz)
{
	int delim = find_new_line_offt(mbuf, sz);
	if (delim == -1)
		return -1;

	mbuf[delim] = 0x00;
	maps_add_entry(mbuf);
	delim++;
	if (delim > sz)
		return sz;

	memmove(mbuf, mbuf + delim, sz - delim);
	memset(mbuf + sz - delim, 0x00, delim);
	return delim;
}

static int maps_cache_create(void)
{
	int mbuf_sz = 2 * PATH_MAX;
	char mbuf[mbuf_sz];
	int num_read;
	int total_read = 0;

	int fd = open("/proc/self/maps", O_RDONLY);
	if (fd < 0)
		return -EINVAL;

	memset(mbuf, 0x00, mbuf_sz);
	while (1) {
		num_read = read(fd, mbuf + total_read, mbuf_sz - total_read);
		if (num_read == -1) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (num_read == 0)
			break;

		total_read += num_read;
		while (1) {
			int processed = process_maps_buffer(mbuf, total_read);

			if (processed  < 1)
				break;
			total_read -= processed;
			if (total_read < 0) {
				total_read = 0;
				break;
			}
		}
	}

	close(fd);
	return 0;
}

/*
 * Must be called under read lock; returnes under read lock.
 */
static int maps_cache_reinit(void)
{
	/*
	 * Drop the read lock and acquire the write one
	 */
	pthread_rwlock_unlock(&lock);
	if (pthread_rwlock_wrlock(&lock) != 0)
		abort();

	/*
	 * Someone else might have re-inited maps cache while we
	 * in unlocked state.
	 */
	if (!(deferred_flush || !mmap_cache_max_id))
		goto out;

	/*
	 * We don't free the mmap_cache table, reuse it instead.
	 */
	if (!mmap_cache)
		mmap_cache = malloc(mmap_cache_sz * sizeof(struct mmap_entry));
	if (!mmap_cache)
		abort();

	mmap_cache_max_id = 0;
	deferred_flush = 0;
	maps_cache_create();

out:
	/*
	 * Drop thr write lock and re-take the read one
	 */
	pthread_rwlock_unlock(&lock);
	if (pthread_rwlock_rdlock(&lock) != 0)
		abort();
	return 0;
}

/*
 * Do not do maps_cache_reinit() from dlclose() path.
 * Deferre cache re-init to a later stage.
 */
int maps_cache_deferred_flush(void)
{
	deferred_flush = 1;
	return 0;
}

int maps_cache_lookup(unsigned long ip)
{
	int lo = 0, hi = mmap_cache_max_id - 1, mid;
	int redo = 0;
	int ret = -1;

	if (pthread_rwlock_rdlock(&lock) != 0)
		abort();

	if (deferred_flush)
		maps_cache_reinit();

	if (mmap_cache_max_id) {
		/*
		 * Fast path.
		 *
		 * We don't expect any new PROT_EXEC mappings below
		 * our currently known LOW.
		 *
		 * This is not always true for MAPPING above our known
		 * HIGH limit. But this should be handled by deferred
		 * from MMPA(PROT_EXEC) path.
		 */
		if (ip < mmap_cache[lo].low || ip > mmap_cache[hi].high)
			goto out;
	}

again:
	/* reset after possible maps_cache_reinit() */
	lo = 0, hi = mmap_cache_max_id - 1;
	mid = 0;

	while (lo <= hi) {
		mid = lo + (hi - lo) / 2;
		if (mmap_cache[mid].low <= ip &&
				ip <= mmap_cache[mid].high) {
			ret = 0;
			goto out;
		}
		if (mmap_cache[mid].low > ip)
			hi = mid - 1;
		if (mmap_cache[mid].low < ip)
			lo = mid + 1;
	}

	/*
	 * If we can't resolve IP - try to re-init the maps cache.
	 * May be we missed MMAP(PROT_EXEC) or something. So we
	 * re-read the /proc/self/maps file and try IP resultion
	 * one more time (just one).
	 */
	if (redo == 0) {
		redo++;
		maps_cache_reinit();
		goto again;
	}

out:
	pthread_rwlock_unlock(&lock);
	return ret;
}

/*
 * This is early init. Do not allocate dynamic buffers here, since
 * we are still in __init mode.
 */
int early_maps_cache_init()
{
	if (pthread_rwlock_init(&lock, NULL) != 0)
		abort;
}
