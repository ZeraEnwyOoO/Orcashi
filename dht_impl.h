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

/* ============================================================================
 * Required DHT Callback Functions
 * ============================================================================ */

/**
 * dht_hash - Hash function for DHT
 * 
 * Computes a hash of up to three data blocks using FNV-1a algorithm.
 * Used for DHT node IDs and tokens.
 * 
 * @param hash_return  Output buffer for hash (must be at least hash_size bytes)
 * @param hash_size    Size of output buffer (usually 8 or 20 bytes)
 * @param v1           First data block (can be NULL if len1 == 0)
 * @param len1         Length of first data block
 * @param v2           Second data block (can be NULL if len2 == 0)
 * @param len2         Length of second data block
 * @param v3           Third data block (can be NULL if len3 == 0)
 * @param len3         Length of third data block
 */
void dht_hash(void *hash_return, int hash_size,
              const void *v1, int len1,
              const void *v2, int len2,
              const void *v3, int len3);

/**
 * dht_blacklisted - Check if a node should be blacklisted
 * 
 * Returns 1 if the node should be ignored, 0 otherwise.
 * Used to filter out malicious or broken nodes.
 * 
 * @param sa     Socket address of the node
 * @param salen  Length of socket address
 * @return       1 if blacklisted, 0 otherwise
 */
int dht_blacklisted(const struct sockaddr *sa, int salen);

/**
 * dht_random_bytes - Fill buffer with cryptographically strong random bytes
 * 
 * Uses getrandom() on Linux or fallback to rand() on other systems.
 * 
 * @param buf  Output buffer
 * @param size Number of bytes to generate
 * @return     0 on success, -1 on failure
 */
int dht_random_bytes(void *buf, size_t size);

/**
 * dht_sendto - Send a UDP packet
 * 
 * Wrapper around sendto() for DHT. Handles error checking and logging.
 * 
 * @param sockfd  Socket file descriptor
 * @param buf     Data to send
 * @param len     Length of data
 * @param flags   Send flags (usually 0)
 * @param to      Destination address
 * @param tolen   Length of destination address
 * @return        Number of bytes sent, or -1 on error
 */
int dht_sendto(int sockfd, const void *buf, int len, int flags,
               const struct sockaddr *to, int tolen);

/* ============================================================================
 * Blacklist Management Functions
 * ============================================================================ */

/**
 * dht_blacklist_add - Add a node to blacklist
 * 
 * Adds a node's address to the internal blacklist.
 * The blacklist has a maximum size of 64 entries.
 * 
 * @param sa     Socket address to blacklist
 * @param salen  Length of socket address
 */
void dht_blacklist_add(const struct sockaddr *sa, int salen);

/**
 * dht_blacklist_clear - Clear the entire blacklist
 * 
 * Removes all entries from the blacklist.
 */
void dht_blacklist_clear(void);

/**
 * dht_blacklist_check - Check if address is blacklisted
 * 
 * @param sa     Socket address to check
 * @param salen  Length of socket address
 * @return       1 if blacklisted, 0 otherwise
 */
int dht_blacklist_check(const struct sockaddr *sa, int salen);

/**
 * dht_blacklist_get_count - Get number of blacklisted nodes
 * 
 * @return  Number of entries in blacklist
 */
int dht_blacklist_get_count(void);

/**
 * dht_blacklist_get_entry - Get a blacklist entry by index
 * 
 * @param index    Index of entry (0 to dht_blacklist_get_count() - 1)
 * @param addr     Output buffer for address
 * @param addrlen  Output buffer for address length
 * @return         1 if success, 0 if index out of range
 */
int dht_blacklist_get_entry(int index, struct sockaddr_storage *addr, int *addrlen);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/**
 * dht_compare_ids - Compare two DHT IDs
 * 
 * @param id1  First ID (20 bytes)
 * @param id2  Second ID (20 bytes)
 * @return     0 if equal, <0 if id1 < id2, >0 if id1 > id2
 */
int dht_compare_ids(const unsigned char *id1, const unsigned char *id2);

/**
 * dht_id_to_string - Convert DHT ID to hex string
 * 
 * @param id     DHT ID (20 bytes)
 * @param buf    Output buffer (must be at least 41 bytes)
 * @param buflen Size of output buffer
 */
void dht_id_to_string(const unsigned char *id, char *buf, int buflen);

/**
 * dht_string_to_id - Convert hex string to DHT ID
 * 
 * @param str    Hex string (40 characters)
 * @param id     Output buffer (20 bytes)
 * @return       1 if success, 0 if invalid string
 */
int dht_string_to_id(const char *str, unsigned char *id);

/* ============================================================================
 * Debug Control
 * ============================================================================ */

/**
 * dht_debug_enable - Enable debug output
 * 
 * @param filename  File to write debug output to (NULL for stderr)
 */
void dht_debug_enable(const char *filename);

/**
 * dht_debug_disable - Disable debug output
 */
void dht_debug_disable(void);

/**
 * dht_debug - Global debug FILE pointer
 * 
 * Set to NULL to disable debug output.
 * Set to stderr or a file pointer to enable.
 */
extern FILE *dht_debug;

#ifdef __cplusplus
}
#endif

#endif /* DHT_IMPL_H */
