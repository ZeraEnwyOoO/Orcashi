#ifndef DHT_IMPL_H
#define DHT_IMPL_H

#include <stddef.h>
#include <sys/socket.h>

/**
 * dht_hash - Hash function for DHT
 * 
 * This function computes a hash of up to three data blocks.
 * The hash is used for DHT node IDs and tokens.
 * 
 * @param hash_return  Output buffer for hash
 * @param hash_size    Size of output buffer (usually 8 or 20 bytes)
 * @param v1           First data block
 * @param len1         Length of first data block
 * @param v2           Second data block (can be NULL)
 * @param len2         Length of second data block
 * @param v3           Third data block (can be NULL)
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
 * 
 * @param sa     Socket address of the node
 * @param salen  Length of socket address
 * @return       1 if blacklisted, 0 otherwise
 */
int dht_blacklisted(const struct sockaddr *sa, int salen);

/**
 * dht_random_bytes - Fill buffer with cryptographically strong random bytes
 * 
 * @param buf  Output buffer
 * @param size Number of bytes to generate
 * @return     0 on success, -1 on failure
 */
int dht_random_bytes(void *buf, size_t size);

/**
 * dht_sendto - Send a UDP packet
 * 
 * Wrapper around sendto() for DHT.
 * 
 * @param sockfd  Socket file descriptor
 * @param buf     Data to send
 * @param len     Length of data
 * @param flags   Send flags
 * @param to      Destination address
 * @param tolen   Length of destination address
 * @return        Number of bytes sent, or -1 on error
 */
int dht_sendto(int sockfd, const void *buf, int len, int flags,
               const struct sockaddr *to, int tolen);

/**
 * dht_debug - Debug output function
 * 
 * Called by DHT for debug messages.
 * Set to NULL to disable debug output.
 */
extern FILE *dht_debug;

/**
 * dht_blacklist_add - Add a node to blacklist
 * 
 * @param sa     Socket address to blacklist
 * @param salen  Length of socket address
 */
void dht_blacklist_add(const struct sockaddr *sa, int salen);

/**
 * dht_blacklist_clear - Clear the blacklist
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

#endif /* DHT_IMPL_H */
