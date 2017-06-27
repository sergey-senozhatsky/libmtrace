AC_PREREQ([2.65])

AC_INIT([mtrace],[1.0.0])
AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_MACRO_DIR([config/m4])
AC_CONFIG_AUX_DIR([config/autoconf])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST

case "${host_os}" in
	linux-gnu*) HOST_OS="linux-gnu" ;;
	linux-uclibc*) HOST_OS="linux-gnu" ;;
	*)		AC_MSG_ERROR([unkown host-os ${host_os}]) ;;
esac
AC_SUBST(HOST_OS)

case "${host_cpu}" in
	arm*|sa110)		HOST_CPU="arm" ;;
	i?86|x86_64)	HOST_CPU="x86" ;;
	*)			HOST_CPU="${host_cpu}" ;;
esac
AC_SUBST(HOST_CPU)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
LT_INIT
# libtool-2:  LT_INIT()
AM_INIT_AUTOMAKE([foreign no-exeext dist-bzip2])
AM_MAINTAINER_MODE

dnl Whether we should workaround Tizen.
AC_ARG_WITH(tizen,
	    AS_HELP_STRING([--with-tizen], [Tizen workaround.]),
	    [case "${withval}" in
	     (yes|no) enable_tizen=$withval;;
	     (*) enable_tizen=yes
		     ;;
		esac],[enable_tizen=yes])

case "${enable_tizen}" in
(yes)
AC_DEFINE([HAVE_TIZEN_WORKAROUND], [1], [We workaround Tizen])
  ;;
(*)
  ;;
esac

dnl Whether we should block signals for backtracing.
AC_ARG_WITH(atomic-backtrace,
	    AS_HELP_STRING([--with-atomic-backtrace], [Block signals while backtracing.]),
	    [case "${withval}" in
	     (yes|no) enable_atomic_backtrace=$withval;;
	     (*) enable_atomic_backtrace=yes
		     ;;
		esac],[enable_atomic_backtrace=no])

case "${enable_atomic_backtrace}" in
(yes)
AC_DEFINE([HAVE_ATOMIC_BACKTRACE], [1], [We block signals while backtracing.])
  ;;
(*)
  ;;
esac

dnl Whether we should track memset().
AC_ARG_WITH(memset,
	    AS_HELP_STRING([--with-memset], [Track memset().]),
	    [case "${withval}" in
	     (yes|no) enable_memset=$withval;;
	     (*) enable_memset=yes
		     ;;
		esac],[enable_memset=no])

dnl Whether we should track memmove().
AC_ARG_WITH(memmove,
	    AS_HELP_STRING([--with-memmove], [Track memmove().]),
	    [case "${withval}" in
	     (yes|no) enable_memmove=$withval;;
	     (*) enable_memmove=yes
		     ;;
		esac],[enable_memmove=no])

AC_CHECK_FUNCS([ \
		malloc \
		calloc \
		realloc \
		memalign \
		cfree \
		posix_memalign \
		aligned_alloc \
		valloc \
		pvalloc \
		gettimeofday \
		mmap \
		munmap \
		mmap2 \
		mlock \
		munlock \
		mlockall \
		munlockall
		])

AC_MSG_CHECKING([whether to track memset()])
case "${enable_memset}" in
(yes)
AC_CHECK_FUNCS([memset])
  ;;
(*)
AC_MSG_RESULT([no])
  ;;
esac

AC_MSG_CHECKING([whether to track memmove()])
case "${enable_memmove}" in
(yes)
AC_CHECK_FUNCS([memmove])
  ;;
(*)
AC_MSG_RESULT([no])
  ;;
esac

saved_CPPFLAGS="${CPPFLAGS}"
CPPFLAGS="${CPPFLAGS} ${AM_CPPFLAGS}"
AC_CHECK_HEADERS([libunwind.h], [have_libunwind_h=yes])
AC_CHECK_HEADERS([libunwind-ptrace.h], [have_libunwind_ptrace_h=yes])
CPPFLAGS="${saved_CPPFLAGS}"

case "${host_cpu}" in
	arm*|sa110)	  UNWIND_ARCH="arm" ;;
	i?86)		  UNWIND_ARCH="x86" ;;
	*)		  UNWIND_ARCH="${host_cpu}" ;;
esac

saved_LDFLAGS="${LDFLAGS}"
LDFLAGS="${LDFLAGS} ${AM_LDFLAGS}"
AC_CHECK_LIB([unwind], [backtrace], [libunwind_LIBS=-lunwind],
	     [AC_MSG_ERROR([Couldn't find or use libunwind.])])

AC_CHECK_LIB([unwind-${UNWIND_ARCH}], [_U${UNWIND_ARCH}_init_remote],
	     [libunwind_LIBS="-lunwind-${UNWIND_ARCH} $libunwind_LIBS"],
	     [AC_MSG_ERROR([Couldn't find or use libunwind-${UNWIND_ARCH}.])],
	     [$libunwind_LIBS])

AC_CHECK_LIB([unwind-ptrace], [_UPT_create],
	     [libunwind_LIBS="-lunwind-ptrace $libunwind_LIBS"],
	     [AC_MSG_ERROR([Couldn't find or use libunwind-ptrace.])],
	     [$libunwind_LIBS])

AC_SUBST(libunwind_LIBS)
AC_DEFINE([HAVE_LIBUNWIND], [1], [we have libunwind])
LDFLAGS="${saved_LDFLAGS}"

AC_CHECK_LIB([dl], [dlopen], [libdl_LIBS=-ldl],
	     [AC_MSG_ERROR([Couldn't find or use libdl.])])
AC_DEFINE([HAVE_LIBDL], [1], [we have libdl])
AC_SUBST(libdl_LIBS)
AC_SUBST(libdl_LD_LIBRARY_PATH)

AC_CHECK_LIB([pthread], [pthread_rwlock_init], [libpthread_LIBS=-lpthread],
	     [AC_MSG_ERROR([Couldn't find or use libpthread.])])
AC_DEFINE([HAVE_LIBPTHREAD], [1], [we have libpthread])
AC_SUBST(libpthread_LIBS)
AC_SUBST(libpthread_LD_LIBRARY_PATH)

AC_SUBST(AM_CPPFLAGS)
AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_LDFLAGS)
AC_SUBST(libunwind_LD_LIBRARY_PATH)

AC_CONFIG_FILES([
		 Makefile
		 ])
AC_OUTPUT
