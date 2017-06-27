#ifndef __UNWIND_TRACE_H
#define __UNWIND_TRACE_H

#include <options.h>

extern void unwind_set_depth(int);
extern void unwind_trace(struct options *);

extern void unwind_flush_cache(void);

#endif /* __UNWIND_TRACE_H */
