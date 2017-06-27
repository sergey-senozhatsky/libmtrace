#ifndef _OUTPUT_H
#define _OUTPUT_H

#include <options.h>

void mtrace_init_file(struct options *opts, const char *base_path);

int output(const char *fmt, ...);
int output_event_pid(void);
int output_event_timestamp(void);
void output_commit(struct options *opts);

#endif /* _OUTPUT_H */
