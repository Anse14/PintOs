#include "devices/sleep.h"

struct list *get_sleep_list(void) {
  return &sleep_threads;
}
