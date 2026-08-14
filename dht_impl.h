 #ifndef DHT_IMPL_H
#define DHT_IMPL_H

#include <stdio.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

void dht_hash(void *hash_return, int hash_size,
              const void *v1, int len1,
              const void *v2, int len2,
              const void *v3, int len3);

int dht_blacklisted(const struct sockaddr *sa, int salen);
int dht_random_bytes(void *buf, size_t size);
int dht_sendto(int sockfd, const void *buf, int len, int flags,
               const struct sockaddr *to, int tolen);

void dht_blacklist_add(const struct sockaddr *sa, int salen);
void dht_blacklist_clear(void);
int dht_blacklist_check(const struct sockaddr *sa, int salen);
int dht_blacklist_get_count(void);
int dht_blacklist_get_entry(int index, struct sockaddr_storage *addr, int *addrlen);

int dht_compare_ids(const unsigned char *id1, const unsigned char *id2);
void dht_id_to_string(const unsigned char *id, char *buf, int buflen);
int dht_string_to_id(const char *str, unsigned char *id);

void dht_debug_enable(const char *filename);
void dht_debug_disable(void);

extern FILE *dht_debug;

#ifdef __cplusplus
}
#endif

#endif
