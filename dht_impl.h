 #ifndef DHT_IMPL_H
#define DHT_IMPL_H

#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

void dht_set_log_file(const char* filename);
void dht_set_debug(int enabled);

#ifdef __cplusplus
}
#endif

#endif
