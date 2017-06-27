#ifndef __SYMBOL_LOOKUP_H
#define __SYMBOL_LOOKUP_H

#define UNRESOLVED_SYM_NAME	"?"

#include <options.h>

struct resovled_sym {
	unsigned long	start_ip;
	unsigned long	end_ip;
	unsigned long	nr;
	char		*fn_name;
};

extern struct resovled_sym add_resolved_symbol(struct options *opts,
				unsigned long start_ip,
				unsigned long end_ip,
				char *fn_name);

extern struct resovled_sym lookup_resolved_symbol(unsigned long ip);

extern void early_lookup_init(void);

#endif /* __SYMBOL_LOOKUP_H */
