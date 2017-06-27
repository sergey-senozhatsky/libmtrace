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

#define _GNU_SOURCE

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <output.h>

static __thread int offt = 0;
static __thread char output_buf[2 * DEFAULT_PAGE_SIZE];

static __thread long thread_id = -1;

static int __get_pid(void)
{
	if (thread_id < 0)
#ifdef SYS_gettid
		thread_id = syscall(SYS_gettid);
#else
		thread_id = getpid();
#endif

	return thread_id;
}

int output(const char *fmt, ...)
{
	size_t wr;
	va_list ap;

	va_start(ap, fmt);
	wr = vsnprintf(output_buf + offt,
			sizeof(output_buf) - offt - 1,
			fmt, ap);
	va_end(ap);

	if (wr < 0 || wr > sizeof(output_buf) - offt - 1)
		fprintf(stderr, "ERROR: output buffer is too small %s\n",
				output_buf);

	offt += wr;
	return wr;
}

int output_event_pid(void)
{
	return output("[t:%ld]", __get_pid());
}

int output_event_timestamp(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return output("[t:%lu.%06d] ",
			(unsigned long)tv.tv_sec,
			(int)tv.tv_usec);
}

void output_commit(struct options *opts)
{
	if (offt)
		fprintf(opts->fd, "%s", output_buf);
	offt = 0;
}

static void create_mtrace_file(struct options *opts, const char *base_path)
{
	char fname[4096];
	FILE *out;

	snprintf(fname, sizeof(fname) - 1, "%s/mtrace-%s-%lu",
			base_path,
			program_invocation_short_name,
			__get_pid());

	out = fopen(fname, "w");
	if (!out) {
		fprintf(stderr,
			"can't open %s: %s\n",
			fname, strerror(errno));
		exit(1);
	}

	setvbuf(out, (char *)NULL, _IOLBF, 0);
	fcntl(fileno(out), F_SETFD, FD_CLOEXEC);

	opts->fd = out;

	fprintf(stderr, "\n\n*** Trace file name: `tailf %s'\n\n", fname);
}

void mtrace_init_file(struct options *opts, const char *fname)
{
	create_mtrace_file(opts, fname);
}
