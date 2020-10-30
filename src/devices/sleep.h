#ifndef SLEEP_H
#define SLEEP_H
#include <list.h>

static struct list sleep_threads = LIST_INITIALIZER(sleep_threads);

struct list *get_sleep_list(void);

#endif
