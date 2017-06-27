ACLOCAL_AMFLAGS = -I config/m4

SUBDIRS = \
	. \
	include

lib_LTLIBRARIES = \
	libmtrace.la

libmtrace_la_LDFLAGS = -version-info 1:0:0

libmtrace_la_SOURCES = output.c maps_cache.c symbol_lookup.c unwind_trace.c \
		       libmtrace.c

libmtrace_la_LIBADD = \
	$(libsupcxx_LIBS) \
	$(libstdcxx_LIBS) \
	$(libunwind_LIBS) \
	$(libdl_LIBS) \
	$(libpthread_LIBS)

bin_PROGRAMS = parser

parser_SOURCES = parser.cpp
