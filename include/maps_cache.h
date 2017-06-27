#ifndef __MAPS_H
#define __MAPS_H

extern int maps_cache_deferred_flush(void);
extern int maps_cache_lookup(unsigned long);
extern int early_maps_cache_init(void);

#endif /* __MAPS_H */
