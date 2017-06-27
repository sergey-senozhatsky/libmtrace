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

#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <limits.h>

#ifndef UNW_LOCAL_ONLY
#define UNW_LOCAL_ONLY
#endif
#include <libunwind.h>

#include "config.h"
#include <output.h>
#include <symbol_lookup.h>
#include <unwind_trace.h>
#include <options.h>
#include <maps_cache.h>

#include <event_names.h>

static struct options opts;

static int global_init_done;
static volatile __thread int __tf_depth;

static size_t __init_buffer_offset;
static char __init_buffer[INIT_BUF_SZ];

static int page_size = DEFAULT_PAGE_SIZE;
static int phys_page_size = DEFAULT_PAGE_SIZE;

static void * (*glibc_malloc)(size_t) 				= malloc;
static void * (*glibc_calloc)(size_t, size_t) 			= calloc;
static void * (*glibc_realloc)(void *, size_t) 			= realloc;
static void   (*glibc_free)(void *) 				= free;
#ifdef HAVE_CFREE
static void   (*glibc_cfree)(void *) 				= cfree;
#endif
static void * (*glibc_memalign)(size_t, size_t) 		= memalign;
#ifdef HAVE_VALLOC
static void * (*glibc_valloc)(size_t) 				= valloc;
#endif
#ifdef HAVE_PVALLOC
static void * (*glibc_pvalloc)(size_t) 				= pvalloc;
#endif
#ifdef HAVE_MEMMOVE
static void * (*glibc_memmove)(void *, const void *, size_t)	= memmove;
#endif
#ifdef HAVE_MEMSET
static void * (*glibc_memset)(void *, int, size_t) 		= memset;
#endif
#ifdef HAVE_POSIX_MEMALIGN
static int (*glibc_posix_memalign)(void **, size_t, size_t) 	= posix_memalign;
#endif
#ifdef HAVE_ALIGNED_ALLOC
static void *(*glibc_aligned_alloc)(size_t, size_t)		= aligned_alloc;
#endif

#ifndef __USE_FILE_OFFSET64
static void * (*glibc_mmap)(void *, size_t, int, int,
				int, off_t)			= mmap;
#else
static void * (*glibc_mmap)(void *, size_t, int, int,
				int, off64_t)			= mmap;
#endif
static int (*glibc_munmap)(void *, size_t) 			= munmap;
#ifdef HAVE_MMAP2
static void * (*glibc_mmap2)(void *, size_t, int, int,
				int, off_t)			= mmap2;
#endif
static int (*glibc_mlock)(const void *, size_t)			= mlock;
static int (*glibc_munlock)(const void *, size_t) 		= munlock;
static int (*glibc_mlockall)(int)				= mlockall;
static int (*glibc_munlockall)(void) 				= munlockall;
static char * (*glibc_getenv)(const char *)			= getenv;
static int (*glibc_dlclose)(void *)				= dlclose;

static void __init_mtrace(void);

#define TRACING_DISABLE()	__tf_depth++;
#define TRACING_ENABLE()	__tf_depth--;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned long alloc_min_wmark = 0;
static unsigned long alloc_max_wmark = ULONG_MAX;

static unsigned long memparse(const char *mem)
{
	char *end;

	unsigned long ret = strtoul(mem, &end, 10);

	switch (*end) {
		case 'G':
		case 'g':
			ret <<= 10;
		case 'M':
		case 'm':
			ret <<= 10;
		case 'K':
		case 'k':
			ret <<= 10;
		default:
			break;
	}

	return ret;
}

/*
 * We need to serialize events that update/change RSS in /proc/self/statm.
 *
 * only in OPTS_MEM_GROW_MODE mode, because otherwise we don't care about
 * RSS value.
 */
static void lock_tracer()
{
	if (!(opts.flags & OPTS_MEM_GROW_MODE))
		return;

	if (pthread_mutex_lock(&lock))
		abort();
}

static void unlock_tracer()
{
	if (!(opts.flags & OPTS_MEM_GROW_MODE))
		return;

	pthread_mutex_unlock(&lock);
}

#ifdef HAVE_ATOMIC_BACKTRACE
static __thread sigset_t old_sigset;
static __thread sigset_t new_sigset;

static void __block_all_signals(void)
{
	sigfillset(&new_sigset);
	if (sigprocmask(SIG_BLOCK, &new_sigset, &old_sigset) != 0) {
		fprintf(stderr, "ERROR: unable to block signals\n");
		abort();
	}
}

static void __restore_all_signals(void)
{
	if (sigprocmask(SIG_SETMASK, &old_sigset, NULL) != 0)
		abort();
}

#else /* HAVE_ATOMIC_BACKTRACE */

static void __block_all_signals(void)
{
}

static void __restore_all_signals(void)
{
}
#endif /* HAVE_ATOMIC_BACKTRACE */

static const char *event_name(int type)
{
	if (type >= EVENT_MAX)
		return "ERROR";

	if (opts.flags & OPTS_HUMAN_READABLE)
		return event_names[type].human_name;
	return event_names[type].compact_name;
}

static unsigned long get_memsize(void)
{
/*
          /proc/[pid]/statm
              Provides information about memory usage, measured in pages.
              The columns are:

                  size       (1) total program size
                             (same as VmSize in /proc/[pid]/status)
                  resident   (2) resident set size
                             (same as VmRSS in /proc/[pid]/status)
                  shared     (3) number of resident shared pages (i.e., backed by a file)
                             (same as RssFile+RssShmem in /proc/[pid]/status)
                  text       (4) text (code)
                  lib        (5) library (unused since Linux 2.6; always 0)
                  data       (6) data + stack
                  dt         (7) dirty pages (unused since Linux 2.6; always 0)
*/

	/* VSZ RSS */
	unsigned long mem[2] = {0, 0};
	char buf[64];

	int fd = open("/proc/self/statm", O_RDONLY);
	if (fd < 0)
		return 0;

	memset(buf, 0x00, sizeof(buf));
	if (read(fd, buf, sizeof(buf)) >= sizeof(mem))
		sscanf(buf, "%lu %lu", &mem[0], &mem[1]);

	close(fd);

	/* return RSS. in page_size units */
	return mem[1];
}

/*
    https://sourceware.org/ml/libc-help/2009-06/msg00001.html

    :You really cannot count upon the execution order of constructors across
    :compilation units. All that is guaranteed is that within one compilation
    :unit (one source file) the constructors will execute in order. When you
    :are dealing with more than one compilation unit - all bets are off: all
    :that is guaranteed is that all static constructors will be called before
    :main is called, but in what order? No guarantees.
    :
    :As for the idea of "any ctor like function in a module will be called
    :before any functions in the module are called" - how do you expect that
    :could work? What if a file defines 2 ctor functions, the first of which
    :calls a function within the file? How, then, can both ctor functions be
    :called before the call of the normal function, when it is the first ctor
    :that calls the function?

    in practice this gives a really confusing behavior. for example:

    Program terminated with signal SIGABRT, Aborted.
      0xb2951878 in raise () from /lib/libc.so.6
      0xb2952d3c in abort () from /lib/libc.so.6
      0xb65a3a64 in mmap (__addr=<optimized out>, __len=<optimized out>,
        __prot=<optimized out>, __flags=2, __fd=4, __offset=0) at libmtrace.c:445
      0xb2722882 in buffer_create () from /lib/libtzplatform-config-2.0.so.2
      0xb2723b6e in initialize () from /lib/libtzplatform-config-2.0.so.2
      0xb2723ed0 in _context_getenv_tzplatform_ ()
       from /lib/libtzplatform-config-2.0.so.2
      0xae9a6060 in _GLOBAL__sub_I_TldExtractor.cpp ()
       from /lib/libwbs_common.so.0
      0xb67c571c in call_init.part () from /lib/ld-linux.so.3

    so we have libmtrace.so loaded and glibc functions are getting redirected
    through the libmtrace lib. however, libmtrace constructor is not called
    yet. instead we have a constructor of other ELF that is being executed
    before us, resulting in mmap() at some, when we still didn't have a
    chance to init libmtrace.
*/
static void __init(void)
{
	if (!global_init_done) {
		__block_all_signals();
		if (!__tf_depth) {
			TRACING_DISABLE();
			__init_mtrace();
			TRACING_ENABLE();
		}
		__restore_all_signals();
	}
}

static int event_start_frame(void)
{
	volatile int start;

	TRACING_DISABLE();
	start = __tf_depth - 1;

	if (start == 0) {
		__block_all_signals();
		output_event_pid();
		output_event_timestamp();
	}
	return start == 0;
}

static int is_event_top_frame(void)
{
	return __tf_depth == 1;
}

static int event_end_frame(void)
{
	if (is_event_top_frame()) {
		__restore_all_signals();
		output_commit(&opts);
	}

	TRACING_ENABLE();
}

static int can_backtrace(size_t __size, int type)
{
	if (opts.flags & OPTS_ALLOC_WMARK) {
		if (type > MAX_STATS)
			return 0;

		return alloc_min_wmark <= __size &&
			__size <= alloc_max_wmark;
	}

	if (opts.flags & OPTS_MEM_GROW_MODE) {
		unsigned long __memsz;
		unsigned long __old_memsz;

		__memsz = get_memsize();
		if (__memsz == 0)
			return 0;

		__old_memsz = opts.stats[type];
		/* always update stats */
		opts.stats[type] = __memsz;

		if (type > MAX_STATS)
			return 0;

		if (type == STATS_MMAP_SZ || __memsz > __old_memsz) {
			output("[m:%ld-%ld]\n",
				__old_memsz * page_size,
				__memsz * page_size);
			return 1;
		}
		return 0;
	}

	if (opts.flags & OPTS_FULL_REPORT_MODE)
		return 1;

	if (opts.flags & OPTS_ALLOC_ONLY_MODE) {
		if (type == STATS_MALLOC_SZ || type == STATS_MMAP_SZ)
			return 1;
		return 0;
	}

	if (opts.flags & OPTS_ALLOC_TOP_MODE) {
		if (type > MAX_STATS)
			return 0;

		if (__size > opts.stats[type]) {
			opts.stats[type] = __size;
			return 1;
		}
		return 0;
	}

	return 0;
}

static void *__init_alloc(size_t __size, size_t __alignment)
{
	size_t prev_offset = __init_buffer_offset;

	__size = ALIGN(__size, __alignment);
	__init_buffer_offset += __size;

	if (__init_buffer_offset >= sizeof(__init_buffer)) {
		fprintf(stderr, "ERROR: init buf size exhausted: "
				"%zu requested, %zu available\n",
				__init_buffer_offset, sizeof(__init_buffer));
		abort();
	}

	return __init_buffer + prev_offset;
}

/*
 * Force page-faults
 */
static void *__init_memset(void *__s, int __c, size_t __n)
{
	volatile char *____s = __s;
	volatile int i;

	for (i = 0 ; i < __n; i++)
		____s[i] = 0x00;
	return (void *)____s;
}

static void __init_free(void *ptr)
{
	/* do nothing here */
}

static void *forced_pgfault(void *__s, size_t __n)
{
	if (!(opts.flags & OPTS_MEM_GROW_MODE))
		return __s;

	if (!__s)
		return __s;

	return __init_memset(__s, 0x00, __n);
}

/* Allocate SIZE bytes of memory.  */
void *malloc(size_t __size)
{
	void *ret;

	__init();

	if (!global_init_done)
		return __init_alloc(__size, MIN_ALIGNMENT);

	if (event_start_frame()) {
		lock_tracer();
		output("%s(%lu)", event_name(EVENT_MALLOC), __size);
	}

	ret = glibc_malloc(__size);
	forced_pgfault(ret, __size);

	if (is_event_top_frame()) {
		int trace;

		output("=0x%x\n", ret);
		trace = can_backtrace(__size, STATS_MALLOC_SZ);
		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}

/* Allocate NMEMB elements of SIZE bytes each, all initialized to 0.  */
void *calloc(size_t __nmemb, size_t __size)
{
	void *ret;

	__init();

	if (!global_init_done)
		return __init_alloc(__nmemb * __size, MIN_ALIGNMENT);

	if (event_start_frame()) {
		lock_tracer();
		output("%s(%lu, %lu)",
			event_name(EVENT_CALLOC),
			__nmemb,
			__size);
	}

	ret = glibc_calloc(__nmemb, __size);
	forced_pgfault(ret, __nmemb * __size);

	if (is_event_top_frame()) {
		int trace;

		output("=0x%x\n", ret);
		trace = can_backtrace(__size * __nmemb, STATS_MALLOC_SZ);
		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}

/* Re-allocate the previously allocated block in __ptr, making the new
   block SIZE bytes long.  */
void *realloc(void *__ptr, size_t __size)
{
	void *ret;

	if (!global_init_done) {
		__init_free(__ptr);
		return __init_alloc(__size, MIN_ALIGNMENT);
	}

	if (event_start_frame()) {
		lock_tracer();
		output("%s(0x%x, %lu)",
			event_name(EVENT_REALLOC),
			__ptr,
			__size);
	}

	ret = glibc_realloc(__ptr, __size);

	if (is_event_top_frame()) {
		int trace;

		output("=0x%x\n", ret);
		trace = can_backtrace(__size, STATS_MALLOC_SZ);
		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}

/* Free a block allocated by `malloc', `realloc' or `calloc'.  */
void free(void *__ptr)
{
	if (!global_init_done) {
		__init_free(__ptr);
		return;
	}

	if (event_start_frame()) {
		lock_tracer();
		output("%s(0x%x)\n", event_name(EVENT_FREE), __ptr);
	}

	glibc_free(__ptr);

	if (is_event_top_frame()) {
		int trace = can_backtrace(0, STATS_FREE);

		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
}

#ifdef HAVE_CFREE
/* Free a block allocated by `calloc'. */
void cfree(void *__ptr)
{
	if (!global_init_done) {
		__init_free(__ptr);
		return;
	}

	if (event_start_frame()) {
		lock_tracer();
		output("%s(0x%x)\n", event_name(EVENT_CFREE), __ptr);
	}

	glibc_cfree(__ptr);

	if (is_event_top_frame()) {
		int trace = can_backtrace(0, STATS_FREE);

		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
}
#endif

/* Allocate SIZE bytes allocated to ALIGNMENT bytes.  */
void *memalign(size_t __alignment, size_t __size)
{
	void *ret;

	__init();

	if (!global_init_done)
		return __init_alloc(__size, __alignment);

	if (event_start_frame()) {
		lock_tracer();
		output("%s(%lu, %lu)", event_name(EVENT_MEMALIGN),
				__alignment, __size);
	}

	ret = glibc_memalign(__alignment, __size);
	forced_pgfault(ret, ALIGN(__size, __alignment));

	if (is_event_top_frame()) {
		int trace;

		output("=0x%x\n", ret);
		trace = can_backtrace(ALIGN(__size, __alignment),
				STATS_MALLOC_SZ);
		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}

#ifdef HAVE_POSIX_MEMALIGN
int posix_memalign(void **__memptr, size_t __alignment, size_t __size)
{
	int ret;

	__init();

	if (!global_init_done) {
		*__memptr = __init_alloc(__size, __alignment);
		return 0;
	}

	if (event_start_frame()) {
		lock_tracer();
		output("%s(%lu, %lu)", event_name(EVENT_POSIX_MEMALIGN),
				__alignment, __size);
	}

	ret = glibc_posix_memalign(__memptr, __alignment, __size);
	forced_pgfault(*__memptr, ALIGN(__size, __alignment));

	if (is_event_top_frame()) {
		int trace;

		output("=0x%x\n", *__memptr);
		trace = can_backtrace(ALIGN(__size, __alignment),
				STATS_MALLOC_SZ);
		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}
#endif

#ifdef HAVE_ALIGNED_ALLOC
void *aligned_alloc(size_t __alignment, size_t __size)
{
	void *ret;

	__init();

	if (!global_init_done)
		return __init_alloc(__size, __alignment);

	if (event_start_frame()) {
		lock_tracer();
		output("%s(%lu, %lu)", event_name(EVENT_ALIGNED_ALLOC),
				__alignment, __size);
	}

	ret = glibc_aligned_alloc(__alignment, __size);
	forced_pgfault(ret, ALIGN(__size, __alignment));

	if (is_event_top_frame()) {
		int trace;

		output("=0x%x\n", ret);
		trace = can_backtrace(ALIGN(__size, __alignment),
				STATS_MALLOC_SZ);
		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}
#endif

#ifdef HAVE_VALLOC
/* Allocate SIZE bytes on a page boundary.  */
void *valloc(size_t __size)
{
	void *ret;

	__init();

	if (!global_init_done)
		return __init_alloc(__size, page_size);

	if (event_start_frame()) {
		lock_tracer();
		output("%s(%lu)", event_name(EVENT_VALLOC), __size);
	}

	ret = glibc_valloc(__size);
	forced_pgfault(ret, ALIGN(__size, page_size));

	if (is_event_top_frame()) {
		int trace;

		output("=0x%x\n", ret);
		trace = can_backtrace(ALIGN(__size, page_size),
				STATS_MALLOC_SZ);
		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}
#endif

#ifdef HAVE_PVALLOC
/* Equivalent to valloc(minimum-page-that-holds(n)), that is, round up
   __size to nearest pagesize. */
void *pvalloc(size_t __size)
{
	void *ret;

	__init();

	if (!global_init_done)
		return __init_alloc(__size, phys_page_size);

	if (event_start_frame()) {
		lock_tracer();
		output("%s(%lu)", event_name(EVENT_PVALLOC), __size);
	}

	ret = glibc_pvalloc(__size);
	forced_pgfault(ret, ALIGN(__size, phys_page_size));

	if (is_event_top_frame()) {
		int trace;

		output("=0x%x\n", ret);
		trace = can_backtrace(ALIGN(__size, phys_page_size),
				STATS_MALLOC_SZ);
		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}
#endif

#ifdef HAVE_MEMSET
/* Set N bytes of S to C.  */
void *memset(void *__s, int __c, size_t __n)
{
	void *ret;

	/*
	 * We can't __init() here. Need to do memset() manually.
	 */
	if (!global_init_done)
		return __init_memset(__s, __c, __n);

	if (event_start_frame()) {
		lock_tracer();
		output("%s(0x%x, %d, %lu)",
			event_name(EVENT_MEMSET),
			__s,
			__c,
			__n);
	}

	ret = glibc_memset(__s, __c, __n);

	if (is_event_top_frame()) {
		int trace;

		output("=0x%x\n", ret);
		trace = can_backtrace(__n, STATS_MALLOC_SZ);
		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}
#endif

#ifdef HAVE_MEMMOVE
/* Copy N bytes of SRC to DEST, guaranteeing
   correct behavior for overlapping strings.  */
void *memmove(void *__dest, const void *__src, size_t __n)
{
	void *ret;

	__init();

	if (event_start_frame()) {
		output("%s(0x%x, 0x%x, %lu)",
			event_name(EVENT_MEMMOVE),
			__dest,
			__src,
			__n);
	}

	ret = glibc_memmove(__dest, __src, __n);

	if (is_event_top_frame()) {
		output("=0x%x\n", ret);

		if (can_backtrace(0, STATS_AUX))
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}
#endif

/* Map addresses starting near ADDR and extending for LEN bytes.  from
   OFFSET into the file FD describes according to PROT and FLAGS.  If ADDR
   is nonzero, it is the desired mapping address.  If the MAP_FIXED bit is
   set in FLAGS, the mapping will be at ADDR exactly (which must be
   page-aligned); otherwise the system chooses a convenient nearby address.
   The return value is the actual mapping address chosen or MAP_FAILED
   for errors (in which case `errno' is set).  A successful `mmap' call
   deallocates any previous mapping for the affected region.  */

#ifndef __USE_FILE_OFFSET64
void *mmap(void *__addr, size_t __len, int __prot,
		   int __flags, int __fd, __off_t __offset)
{
	void *ret;

	__init();

	if (!global_init_done)
		abort();

	if (event_start_frame()) {
		lock_tracer();
		output("%s(0x%x, %lu, %d, %d, %d, %lu)",
			event_name(EVENT_MMAP),
			__addr, __len, __prot, __flags,
			__fd, __offset);
	}

	ret = glibc_mmap(__addr, __len, __prot, __flags, __fd, __offset);

	if (__prot & PROT_EXEC)
		maps_cache_deferred_flush();

	if (is_event_top_frame()) {
		int trace;

		output("=0x%x\n", ret);
		trace = can_backtrace(__len, STATS_MMAP_SZ);
		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}
#else
void *mmap(void *__addr, size_t __len, int __prot,
		   int __flags, int __fd, __off64_t __offset)
{
	void *ret;

	__init();

	if (!global_init_done)
		abort();

	if (event_start_frame()) {
		lock_tracer();
		output("%s(0x%x, %lu, %d, %d, %d, %llu)",
			event_name(EVENT_MMAP),
			__addr, __len, __prot, __flags,
			__fd, __offset);
	}

	ret = glibc_mmap(__addr, __len, __prot, __flags, __fd, __offset);

	if (__prot & PROT_EXEC)
		maps_cache_deferred_flush();

	if (is_event_top_frame()) {
		int trace;

		output("=0x%x\n", ret);
		trace = can_backtrace(__len, STATS_MMAP_SZ);
		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}
#endif

/* Deallocate any mapping for the region starting at ADDR and extending LEN
   bytes.  Returns 0 if successful, -1 for errors (and sets errno).  */
int munmap(void *__addr, size_t __len)
{
	int ret;

	if (!global_init_done)
		abort();

	if (event_start_frame()) {
		lock_tracer();
		output("%s(0x%x, %lu)",
			event_name(EVENT_MUNMAP),
			__addr,
			__len);
	}

	ret = glibc_munmap(__addr, __len);

	if (is_event_top_frame()) {
		int trace;

		output("=%d\n", ret);
		trace = can_backtrace(0, STATS_FREE);
		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}

#ifdef HAVE_MMAP2
void *mmap2(void *__addr, size_t __len, int __prot,
		   int __flags, int __fd, off_t __offset)
{
	void *ret;

	__init();

	if (!global_init_done)
		abort();

	if (event_start_frame()) {
		lock_tracer();
		output("%s(0x%x, %lu, %d, %d, %d, %llu)",
			event_name(EVENT_MMAP2),
			__addr, __len, __prot, __flags,
			__fd, __offset);
	}

	ret = glibc_mmap2(__addr, __len, __prot, __flags, __fd, __offset);

	if (__prot & PROT_EXEC)
		maps_cache_deferred_flush();

	if (is_event_top_frame()) {
		int trace;

		output("=0x%x\n", ret);
		trace = can_backtrace(__len, STATS_MMAP_SZ);
		unlock_tracer();
		if (trace)
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}
#endif

/* Guarantee all whole pages mapped by the range [ADDR,ADDR+LEN) to
   be memory resident.  */
int mlock(const void *__addr, size_t __len)
{
	int ret;

	__init();

	if (!global_init_done)
		abort();

	if (event_start_frame()) {
		output("%s(0x%x, %lu)",
			event_name(EVENT_MLOCK),
			__addr,
			__len);
	}

	ret = glibc_mlock(__addr, __len);

	if (is_event_top_frame()) {
		output("=%d\n", ret);

		if (can_backtrace(__len, STATS_MLOCK))
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}

/* Unlock whole pages previously mapped by the range [ADDR,ADDR+LEN).  */
int munlock(const void *__addr, size_t __len)
{
	int ret;

	if (!global_init_done)
		abort();

	if (event_start_frame()) {
		output("%s(0x%x, %lu)",
			event_name(EVENT_MUNLOCK),
			__addr,
			__len);
	}

	ret = glibc_munlock(__addr, __len);

	if (is_event_top_frame()) {
		output("=%d\n", ret);

		if (can_backtrace(__len, STATS_MLOCK))
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}

/* Cause all currently mapped pages of the process to be memory resident
   until unlocked by a call to the `munlockall', until the process exits,
   or until the process calls `execve'.  */
int mlockall(int __flags)
{
	int ret;

	__init();

	if (!global_init_done)
		abort();

	if (event_start_frame()) {
		output("%s(%d)", event_name(EVENT_MLOCKALL), __flags);
	}

	ret = glibc_mlockall(__flags);

	if (is_event_top_frame()) {
		output("=%d\n", ret);

		if (can_backtrace(0, STATS_MLOCK))
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}


/* All currently mapped pages of the process' address space become
   unlocked.  */
int munlockall(void)
{
	int ret;

	if (!global_init_done)
		abort();

	if (event_start_frame()) {
		output("%s()", event_name(EVENT_MUNLOCKALL));
	}

	ret = glibc_munlockall();

	if (is_event_top_frame()) {
		output("=%d\n", ret);

		if (can_backtrace(0, STATS_MLOCK))
			unwind_trace(&opts);
	}
	event_end_frame();
	return ret;
}

char *getenv(const char *name)
{
#ifdef HAVE_TIZEN_WORKAROUND
	/*
	 * Do not use UNW_ARM_METHOD_FRAME with "ARM EABI".
	 * This crashes libunwind on MALI lib and a bunch of other
	 * places. Look at libunwind-1.1/src/arm/Gstep.c, we are
	 * crashing around this place
	 * 	dwarf_get(&c->dwarf, DWARF_LOC(frame, 0), &instr)
	 *
	 * In general libubwind UNW_ARM_#FOO are so unreliable on Tizen
	 * that we even have to use in-house /proc/self/maps cache to
	 * verify that registers returned from libuwind actually belong
	 * to any of PROT_EXEC mappings and won't crash us.
	 */
	if (strcmp(name, "UNW_ARM_UNWIND_METHOD") == 0)
		return "5"; /* UNW_ARM_METHOD_DWARF | UNW_ARM_METHOD_EXIDX */
#endif

	/*
	 * We may deadlock here. Surprise-surprise!
	 *
	 * #0  0x00007f0da5047d8c in __lll_lock_wait ()
	 * #1  0x00007f0da5040c56 in pthread_mutex_lock ()
	 * #2  0x0000556b4eb7d00b in ?? ()
	 * #3  0x0000556b4eb7e105 in calloc ()
	 * #4  0x00007f0da4e3473f in ?? ()
	 * #5  0x00007f0da4e34128 in dlsym ()
	 * #6  0x00007f0da5258e15 in __init_mtrace ()
	 * #7  __init () at libmtrace.c:170
	 * #8  0x00007f0da5259068 in __init ()
	 * #9  getenv (name=0x556b4eb80877 "MALLOC_OPTIONS")
	 * #10 0x0000556b4eb7d0bb in ?? ()
	 * #11 0x0000556b4eb7da70 in malloc ()
	 * #12 0x00007f0da4b82e06 in (anonymous namespace)::pool::pool (...)
	 * #13 __static_initialization_and_destruction_0 (...)
	 * #14 _GLOBAL__sub_I_eh_alloc.cc(void) ()
	 * #15 0x00007f0da566c34a in call_init.part ()
	 * #16 0x00007f0da566c45b in _dl_init ()
	 * #17 0x00007f0da565ddba in _dl_start_user ()
	 */
	if (strcmp(name, "MALLOC_OPTIONS") == 0)
		return NULL;

	__init();

	if (!global_init_done)
		abort();

	return glibc_getenv(name);
}

int dlclose(void *handle)
{
	int ret;

	if (!global_init_done)
		abort();

	ret = glibc_dlclose(handle);

	/*
	 * Caching policy is turned on for UW local address space,
	 * must flush the address space to avoid stale data reads.
	 */
	TRACING_DISABLE();
	unwind_flush_cache();
	maps_cache_deferred_flush();
	TRACING_ENABLE();
	return ret;
}

/*
 * __attribute__ constructor does not work. read __init() comment.
 */
static void __init_mtrace(void)
{
	if (global_init_done == 1)
		return;

	opts.fd = stderr;
	opts.flags = OPTS_MEM_GROW_MODE;

	page_size = sysconf(_SC_PAGESIZE);
	phys_page_size = sysconf(_SC_PHYS_PAGES);

	glibc_malloc		= dlsym(RTLD_NEXT, "malloc");
	glibc_calloc		= dlsym(RTLD_NEXT, "calloc");
	glibc_realloc		= dlsym(RTLD_NEXT, "realloc");
	glibc_free		= dlsym(RTLD_NEXT, "free");
#ifdef HAVE_CFREE
	glibc_cfree		= dlsym(RTLD_NEXT, "cfree");
#endif
	glibc_memalign		= dlsym(RTLD_NEXT, "memalign");
#ifdef HAVE_POSIX_MEMALIGN
	glibc_posix_memalign	= dlsym(RTLD_NEXT, "posix_memalign");
#endif
#ifdef HAVE_ALIGNED_ALLOC
	glibc_aligned_alloc	= dlsym(RTLD_NEXT, "aligned_alloc");
#endif
#ifdef HAVE_VALLOC
	glibc_valloc		= dlsym(RTLD_NEXT, "valloc");
#endif
#ifdef HAVE_PVALLOC
	glibc_pvalloc		= dlsym(RTLD_NEXT, "pvalloc");
#endif
#ifdef HAVE_MEMSET
	glibc_memset		= dlsym(RTLD_NEXT, "memset");
#endif
#ifdef HAVE_MEMMOVE
	glibc_memmove		= dlsym(RTLD_NEXT, "memmove");
#endif

	glibc_mmap		= dlsym(RTLD_NEXT, "mmap");
	glibc_munmap		= dlsym(RTLD_NEXT, "munmap");
#ifdef HAVE_MMAP2
	glibc_mmap2		= dlsym(RTLD_NEXT, "mmap2");
#endif
	glibc_mlock		= dlsym(RTLD_NEXT, "mlock");
	glibc_munlock		= dlsym(RTLD_NEXT, "munlock");
	glibc_mlockall		= dlsym(RTLD_NEXT, "mlockall");
	glibc_munlockall	= dlsym(RTLD_NEXT, "munlockall");
	glibc_getenv            = dlsym(RTLD_NEXT, "getenv");
	glibc_dlclose		= dlsym(RTLD_NEXT, "dlclose");

	early_lookup_init();
	early_maps_cache_init();

	global_init_done = 1;

	if (getenv("MTRACE_BACKTRACE_DEPTH")) {
		char *depth = getenv("MTRACE_BACKTRACE_DEPTH");
		int dep = atoi(depth);

		if (dep < 0)
			dep = 0;
		unwind_set_depth(dep);
	}

	if (getenv("MTRACE_LOG_DIR")) {
		const char *base_path = getenv("MTRACE_LOG_DIR");

		mtrace_init_file(&opts, base_path);
	}

	if (getenv("MTRACE_REPORTING_MODE")) {
		char *mode = getenv("MTRACE_REPORTING_MODE");

		if (!strcmp(mode, "atop")) {
			opts.flags = OPTS_ALLOC_TOP_MODE;
		}

		if (!strcmp(mode, "full")) {
			opts.flags = OPTS_FULL_REPORT_MODE;
		}

		if (!strcmp(mode, "alloc")) {
			opts.flags = OPTS_ALLOC_ONLY_MODE;
		}
	}

	if (getenv("MTRACE_ALLOC_MINWMARK")) {
		char *wmark = getenv("MTRACE_ALLOC_MINWMARK");

		alloc_min_wmark = memparse(wmark);
		opts.flags = OPTS_ALLOC_WMARK;
	}

	if (getenv("MTRACE_ALLOC_MAXWMARK")) {
		char *wmark = getenv("MTRACE_ALLOC_MAXWMARK");

		alloc_max_wmark = memparse(wmark);
		opts.flags = OPTS_ALLOC_WMARK;
	}

	if (getenv("MTRACE_HUMAN_READABLE"))
		opts.flags |= OPTS_HUMAN_READABLE;
}
