 // dht_impl.c - DHT Implementation for jech/dht (EVP API)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

int dht_blacklisted(const struct sockaddr *sa, int salen) {
    return 0;
}

int dht_random_bytes(void *buf, size_t size) {
    FILE* f = fopen("/dev/urandom", "r");
    if (f) {
        size_t n = fread(buf, 1, size, f);
        fclose(f);
        return n == size ? 0 : -1;
    }
    unsigned char* b = (unsigned char*)buf;
    for (size_t i = 0; i < size; i++) {
        b[i] = rand() & 0xFF;
    }
    return 0;
}

void dht_hash(void *hash_return, int hash_size,
              const void *data1, int len1,
              const void *data2, int len2,
              const void *data3, int len3) {
    unsigned char hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data1, len1);
    if (data2) EVP_DigestUpdate(ctx, data2, len2);
    if (data3) EVP_DigestUpdate(ctx, data3, len3);
    unsigned int len = 32;
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    memcpy(hash_return, hash, hash_size > 32 ? 32 : hash_size);
}

int dht_sendto(int sockfd, const void *buf, int len, int flags,
               const struct sockaddr *dest_addr, int addrlen) {
    return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}
