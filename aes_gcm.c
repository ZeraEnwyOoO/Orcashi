// aes_gcm.c - Full implementation of AES-256-GCM encryption for Orcashi
#include "aes_gcm.h"
#include "orca_crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* ============================================================================
 * STATIC HELPERS
 * ============================================================================ */

static void set_aes_error(const char* msg) {
    orca_clear_error();
    fprintf(stderr, "[AES-GCM ERROR] %s\n", msg);
}

static int openssl_aes_init(void) {
    static int initialized = 0;
    if (!initialized) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        initialized = 1;
    }
    return 0;
}

static void zeroize(void* ptr, size_t len) {
    if (ptr && len > 0) {
        volatile char* vptr = (volatile char*)ptr;
        for (size_t i = 0; i < len; i++) {
            vptr[i] = 0;
        }
    }
}

/* ============================================================================
 * KEY MANAGEMENT
 * ============================================================================ */

int orca_aes_gcm_key_generate(unsigned char* key_out) {
    if (!key_out) {
        set_aes_error("NULL pointer in orca_aes_gcm_key_generate");
        return -1;
    }
    
    openssl_aes_init();
    
    if (RAND_bytes(key_out, ORCA_AES_GCM_KEY_LEN) != 1) {
        set_aes_error("Failed to generate random key");
        return -1;
    }
    
    return 0;
}

int orca_aes_gcm_key_from_hex(const char* hex, unsigned char* key_out) {
    if (!hex || !key_out) {
        set_aes_error("NULL pointer in orca_aes_gcm_key_from_hex");
        return -1;
    }
    return orca_hex_to_bytes(hex, key_out, ORCA_AES_GCM_KEY_LEN);
}

char* orca_aes_gcm_key_to_hex(const unsigned char* key, char* hex_out) {
    if (!key || !hex_out) return NULL;
    return orca_bytes_to_hex(key, ORCA_AES_GCM_KEY_LEN, hex_out);
}

void orca_aes_gcm_key_zeroize(unsigned char* key) {
    if (key) {
        zeroize(key, ORCA_AES_GCM_KEY_LEN);
    }
}

/* ============================================================================
 * IV / NONCE MANAGEMENT
 * ============================================================================ */

int orca_aes_gcm_nonce_generate(unsigned char* nonce_out) {
    if (!nonce_out) {
        set_aes_error("NULL pointer in orca_aes_gcm_nonce_generate");
        return -1;
    }
    
    openssl_aes_init();
    
    if (RAND_bytes(nonce_out, ORCA_AES_GCM_NONCE_LEN) != 1) {
        set_aes_error("Failed to generate random nonce");
        return -1;
    }
    
    return 0;
}

int orca_aes_gcm_nonce_from_hex(const char* hex, unsigned char* nonce_out) {
    if (!hex || !nonce_out) {
        set_aes_error("NULL pointer in orca_aes_gcm_nonce_from_hex");
        return -1;
    }
    return orca_hex_to_bytes(hex, nonce_out, ORCA_AES_GCM_NONCE_LEN);
}

char* orca_aes_gcm_nonce_to_hex(const unsigned char* nonce, char* hex_out) {
    if (!nonce || !hex_out) return NULL;
    return orca_bytes_to_hex(nonce, ORCA_AES_GCM_NONCE_LEN, hex_out);
}

int orca_aes_gcm_nonce_increment(unsigned char* nonce) {
    if (!nonce) {
        set_aes_error("NULL pointer in orca_aes_gcm_nonce_increment");
        return -1;
    }
    
    // Increment as big-endian 96-bit number
    for (int i = ORCA_AES_GCM_NONCE_LEN - 1; i >= 0; i--) {
        nonce[i]++;
        if (nonce[i] != 0) break;
    }
    
    return 0;
}

int orca_aes_gcm_nonce_increment_hex(char* nonce_hex) {
    if (!nonce_hex) {
        set_aes_error("NULL pointer in orca_aes_gcm_nonce_increment_hex");
        return -1;
    }
    
    unsigned char nonce[ORCA_AES_GCM_NONCE_LEN];
    if (orca_hex_to_bytes(nonce_hex, nonce, ORCA_AES_GCM_NONCE_LEN) < 0) {
        set_aes_error("Invalid nonce hex");
        return -1;
    }
    
    orca_aes_gcm_nonce_increment(nonce);
    orca_bytes_to_hex(nonce, ORCA_AES_GCM_NONCE_LEN, nonce_hex);
    
    return 0;
}

void orca_aes_gcm_nonce_zeroize(unsigned char* nonce) {
    if (nonce) {
        zeroize(nonce, ORCA_AES_GCM_NONCE_LEN);
    }
}

/* ============================================================================
 * ENCRYPTION
 * ============================================================================ */

int orca_aes_gcm_encrypt(const unsigned char* plaintext, size_t plaintext_len,
                         const unsigned char* key,
                         const unsigned char* nonce,
                         unsigned char* tag_out,
                         unsigned char** ciphertext_out,
                         size_t* ciphertext_len) {
    if (!plaintext || !key || !nonce || !tag_out || !ciphertext_out || !ciphertext_len) {
        set_aes_error("NULL pointer in orca_aes_gcm_encrypt");
        return -1;
    }
    
    openssl_aes_init();
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        set_aes_error("Failed to create cipher context");
        return -1;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        set_aes_error("Failed to init encryption");
        return -1;
    }
    
    *ciphertext_out = (unsigned char*)malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    if (!*ciphertext_out) {
        EVP_CIPHER_CTX_free(ctx);
        set_aes_error("malloc failed for ciphertext");
        return -1;
    }
    
    int len, total_len = 0;
    if (EVP_EncryptUpdate(ctx, *ciphertext_out, &len, plaintext, plaintext_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext_out);
        *ciphertext_out = NULL;
        set_aes_error("Failed to encrypt data");
        return -1;
    }
    total_len += len;
    
    if (EVP_EncryptFinal_ex(ctx, *ciphertext_out + total_len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext_out);
        *ciphertext_out = NULL;
        set_aes_error("Failed to finalize encryption");
        return -1;
    }
    total_len += len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ORCA_AES_GCM_TAG_LEN, tag_out) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext_out);
        *ciphertext_out = NULL;
        set_aes_error("Failed to get GCM tag");
        return -1;
    }
    
    *ciphertext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int orca_aes_gcm_encrypt_string(const char* plaintext, const char* key_hex,
                                char* nonce_hex_out, char* tag_hex_out,
                                char** ciphertext_b64_out) {
    if (!plaintext || !key_hex || !nonce_hex_out || !tag_hex_out || !ciphertext_b64_out) {
        set_aes_error("NULL pointer in orca_aes_gcm_encrypt_string");
        return -1;
    }
    
    unsigned char key[ORCA_AES_GCM_KEY_LEN];
    if (orca_hex_to_bytes(key_hex, key, ORCA_AES_GCM_KEY_LEN) < 0) {
        set_aes_error("Invalid key hex");
        return -1;
    }
    
    unsigned char nonce[ORCA_AES_GCM_NONCE_LEN];
    if (orca_aes_gcm_nonce_generate(nonce) < 0) {
        zeroize(key, ORCA_AES_GCM_KEY_LEN);
        set_aes_error("Failed to generate nonce");
        return -1;
    }
    
    unsigned char tag[ORCA_AES_GCM_TAG_LEN];
    unsigned char* ciphertext;
    size_t ciphertext_len;
    
    if (orca_aes_gcm_encrypt((const unsigned char*)plaintext, strlen(plaintext),
                             key, nonce, tag, &ciphertext, &ciphertext_len) < 0) {
        zeroize(key, ORCA_AES_GCM_KEY_LEN);
        zeroize(nonce, ORCA_AES_GCM_NONCE_LEN);
        return -1;
    }
    
    orca_bytes_to_hex(nonce, ORCA_AES_GCM_NONCE_LEN, nonce_hex_out);
    orca_bytes_to_hex(tag, ORCA_AES_GCM_TAG_LEN, tag_hex_out);
    
    *ciphertext_b64_out = orca_base64_encode(ciphertext, ciphertext_len);
    free(ciphertext);
    
    zeroize(key, ORCA_AES_GCM_KEY_LEN);
    zeroize(nonce, ORCA_AES_GCM_NONCE_LEN);
    
    if (!*ciphertext_b64_out) {
        set_aes_error("Failed to base64 encode ciphertext");
        return -1;
    }
    
    return 0;
}

int orca_aes_gcm_encrypt_message(const unsigned char* plaintext, size_t plaintext_len,
                                 const unsigned char* key,
                                 OrcaAESGCMMessage* message_out) {
    if (!plaintext || !key || !message_out) {
        set_aes_error("NULL pointer in orca_aes_gcm_encrypt_message");
        return -1;
    }
    
    memset(message_out, 0, sizeof(OrcaAESGCMMessage));
    memcpy(message_out->key.key, key, ORCA_AES_GCM_KEY_LEN);
    message_out->plaintext_len = plaintext_len;
    message_out->plaintext = (unsigned char*)malloc(plaintext_len);
    if (!message_out->plaintext) {
        set_aes_error("malloc failed for plaintext");
        return -1;
    }
    memcpy(message_out->plaintext, plaintext, plaintext_len);
    
    if (orca_aes_gcm_nonce_generate(message_out->nonce.nonce) < 0) {
        free(message_out->plaintext);
        set_aes_error("Failed to generate nonce");
        return -1;
    }
    
    if (orca_aes_gcm_encrypt(plaintext, plaintext_len,
                             key, message_out->nonce.nonce,
                             message_out->tag.tag,
                             &message_out->ciphertext,
                             &message_out->ciphertext_len) < 0) {
        free(message_out->plaintext);
        return -1;
    }
    
    message_out->encrypted = true;
    return 0;
}

int orca_aes_gcm_encrypt_stream(const unsigned char* key,
                                const unsigned char* nonce,
                                const unsigned char* chunk, size_t chunk_len,
                                unsigned char** ciphertext_out,
                                size_t* ciphertext_len,
                                bool is_final,
                                unsigned char* tag_out) {
    if (!key || !nonce || !chunk || !ciphertext_out || !ciphertext_len) {
        set_aes_error("NULL pointer in orca_aes_gcm_encrypt_stream");
        return -1;
    }
    
    openssl_aes_init();
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        set_aes_error("Failed to create cipher context");
        return -1;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        set_aes_error("Failed to init encryption");
        return -1;
    }
    
    *ciphertext_out = (unsigned char*)malloc(chunk_len + EVP_MAX_BLOCK_LENGTH);
    if (!*ciphertext_out) {
        EVP_CIPHER_CTX_free(ctx);
        set_aes_error("malloc failed for ciphertext");
        return -1;
    }
    
    int len, total_len = 0;
    if (EVP_EncryptUpdate(ctx, *ciphertext_out, &len, chunk, chunk_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext_out);
        *ciphertext_out = NULL;
        set_aes_error("Failed to encrypt chunk");
        return -1;
    }
    total_len += len;
    
    if (is_final) {
        if (EVP_EncryptFinal_ex(ctx, *ciphertext_out + total_len, &len) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            free(*ciphertext_out);
            *ciphertext_out = NULL;
            set_aes_error("Failed to finalize encryption");
            return -1;
        }
        total_len += len;
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, ORCA_AES_GCM_TAG_LEN, tag_out) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            free(*ciphertext_out);
            *ciphertext_out = NULL;
            set_aes_error("Failed to get GCM tag");
            return -1;
        }
    }
    
    *ciphertext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/* ============================================================================
 * DECRYPTION
 * ============================================================================ */

int orca_aes_gcm_decrypt(const unsigned char* ciphertext, size_t ciphertext_len,
                         const unsigned char* key,
                         const unsigned char* nonce,
                         const unsigned char* tag,
                         unsigned char** plaintext_out,
                         size_t* plaintext_len) {
    if (!ciphertext || !key || !nonce || !tag || !plaintext_out || !plaintext_len) {
        set_aes_error("NULL pointer in orca_aes_gcm_decrypt");
        return -1;
    }
    
    openssl_aes_init();
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        set_aes_error("Failed to create cipher context");
        return -1;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        set_aes_error("Failed to init decryption");
        return -1;
    }
    
    *plaintext_out = (unsigned char*)malloc(ciphertext_len + 1);
    if (!*plaintext_out) {
        EVP_CIPHER_CTX_free(ctx);
        set_aes_error("malloc failed for plaintext");
        return -1;
    }
    
    int len, total_len = 0;
    if (EVP_DecryptUpdate(ctx, *plaintext_out, &len, ciphertext, ciphertext_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext_out);
        *plaintext_out = NULL;
        set_aes_error("Failed to decrypt data");
        return -1;
    }
    total_len += len;
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ORCA_AES_GCM_TAG_LEN, (void*)tag) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext_out);
        *plaintext_out = NULL;
        set_aes_error("Failed to set GCM tag");
        return -1;
    }
    
    int ret = EVP_DecryptFinal_ex(ctx, *plaintext_out + total_len, &len);
    if (ret <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext_out);
        *plaintext_out = NULL;
        set_aes_error("Authentication failed - invalid tag");
        return -1;
    }
    total_len += len;
    
    *plaintext_len = total_len;
    (*plaintext_out)[total_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int orca_aes_gcm_decrypt_string(const char* ciphertext_b64, const char* nonce_hex,
                                const char* tag_hex, const char* key_hex,
                                char** plaintext_out) {
    if (!ciphertext_b64 || !nonce_hex || !tag_hex || !key_hex || !plaintext_out) {
        set_aes_error("NULL pointer in orca_aes_gcm_decrypt_string");
        return -1;
    }
    
    unsigned char key[ORCA_AES_GCM_KEY_LEN];
    if (orca_hex_to_bytes(key_hex, key, ORCA_AES_GCM_KEY_LEN) < 0) {
        set_aes_error("Invalid key hex");
        return -1;
    }
    
    unsigned char nonce[ORCA_AES_GCM_NONCE_LEN];
    if (orca_hex_to_bytes(nonce_hex, nonce, ORCA_AES_GCM_NONCE_LEN) < 0) {
        zeroize(key, ORCA_AES_GCM_KEY_LEN);
        set_aes_error("Invalid nonce hex");
        return -1;
    }
    
    unsigned char tag[ORCA_AES_GCM_TAG_LEN];
    if (orca_hex_to_bytes(tag_hex, tag, ORCA_AES_GCM_TAG_LEN) < 0) {
        zeroize(key, ORCA_AES_GCM_KEY_LEN);
        zeroize(nonce, ORCA_AES_GCM_NONCE_LEN);
        set_aes_error("Invalid tag hex");
        return -1;
    }
    
    int ciphertext_len;
    unsigned char* ciphertext = orca_base64_decode(ciphertext_b64, &ciphertext_len);
    if (!ciphertext) {
        zeroize(key, ORCA_AES_GCM_KEY_LEN);
        zeroize(nonce, ORCA_AES_GCM_NONCE_LEN);
        set_aes_error("Failed to decode ciphertext");
        return -1;
    }
    
    unsigned char* plaintext;
    size_t plaintext_len;
    
    int result = orca_aes_gcm_decrypt(ciphertext, ciphertext_len,
                                      key, nonce, tag, &plaintext, &plaintext_len);
    free(ciphertext);
    zeroize(key, ORCA_AES_GCM_KEY_LEN);
    zeroize(nonce, ORCA_AES_GCM_NONCE_LEN);
    
    if (result < 0) {
        return -1;
    }
    
    *plaintext_out = (char*)plaintext;
    return 0;
}

int orca_aes_gcm_decrypt_message(const OrcaAESGCMMessage* message,
                                 const unsigned char* key,
                                 unsigned char** plaintext_out,
                                 size_t* plaintext_len) {
    if (!message || !key || !plaintext_out || !plaintext_len) {
        set_aes_error("NULL pointer in orca_aes_gcm_decrypt_message");
        return -1;
    }
    
    if (!message->encrypted) {
        set_aes_error("Message is not encrypted");
        return -1;
    }
    
    return orca_aes_gcm_decrypt(message->ciphertext, message->ciphertext_len,
                                key, message->nonce.nonce,
                                message->tag.tag,
                                plaintext_out, plaintext_len);
}

int orca_aes_gcm_decrypt_stream(const unsigned char* key,
                                const unsigned char* nonce,
                                const unsigned char* ciphertext, size_t ciphertext_len,
                                unsigned char** plaintext_out,
                                size_t* plaintext_len,
                                bool is_final,
                                const unsigned char* tag) {
    if (!key || !nonce || !ciphertext || !plaintext_out || !plaintext_len) {
        set_aes_error("NULL pointer in orca_aes_gcm_decrypt_stream");
        return -1;
    }
    
    openssl_aes_init();
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        set_aes_error("Failed to create cipher context");
        return -1;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        set_aes_error("Failed to init decryption");
        return -1;
    }
    
    *plaintext_out = (unsigned char*)malloc(ciphertext_len + 1);
    if (!*plaintext_out) {
        EVP_CIPHER_CTX_free(ctx);
        set_aes_error("malloc failed for plaintext");
        return -1;
    }
    
    int len, total_len = 0;
    if (EVP_DecryptUpdate(ctx, *plaintext_out, &len, ciphertext, ciphertext_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext_out);
        *plaintext_out = NULL;
        set_aes_error("Failed to decrypt chunk");
        return -1;
    }
    total_len += len;
    
    if (is_final) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, ORCA_AES_GCM_TAG_LEN, (void*)tag) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            free(*plaintext_out);
            *plaintext_out = NULL;
            set_aes_error("Failed to set GCM tag");
            return -1;
        }
        
        int ret = EVP_DecryptFinal_ex(ctx, *plaintext_out + total_len, &len);
        if (ret <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            free(*plaintext_out);
            *plaintext_out = NULL;
            set_aes_error("Authentication failed - invalid tag");
            return -1;
        }
        total_len += len;
    }
    
    *plaintext_len = total_len;
    (*plaintext_out)[total_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/* ============================================================================
 * MESSAGE SERIALIZATION
 * ============================================================================ */

int orca_aes_gcm_message_serialize(const OrcaAESGCMMessage* message,
                                   unsigned char** buffer_out,
                                   size_t* buffer_len) {
    if (!message || !buffer_out || !buffer_len) {
        set_aes_error("NULL pointer in orca_aes_gcm_message_serialize");
        return -1;
    }
    
    if (!message->encrypted) {
        set_aes_error("Message is not encrypted");
        return -1;
    }
    
    // Format: [nonce(12)][tag(16)][ciphertext_len(4)][ciphertext]
    size_t total_len = ORCA_AES_GCM_NONCE_LEN + ORCA_AES_GCM_TAG_LEN + 4 + message->ciphertext_len;
    *buffer_out = (unsigned char*)malloc(total_len);
    if (!*buffer_out) {
        set_aes_error("malloc failed for serialization");
        return -1;
    }
    
    unsigned char* ptr = *buffer_out;
    memcpy(ptr, message->nonce.nonce, ORCA_AES_GCM_NONCE_LEN);
    ptr += ORCA_AES_GCM_NONCE_LEN;
    
    memcpy(ptr, message->tag.tag, ORCA_AES_GCM_TAG_LEN);
    ptr += ORCA_AES_GCM_TAG_LEN;
    
    // Store ciphertext length as 4-byte big-endian
    uint32_t len_be = htonl((uint32_t)message->ciphertext_len);
    memcpy(ptr, &len_be, 4);
    ptr += 4;
    
    memcpy(ptr, message->ciphertext, message->ciphertext_len);
    
    *buffer_len = total_len;
    return 0;
}

int orca_aes_gcm_message_deserialize(const unsigned char* buffer,
                                     size_t buffer_len,
                                     OrcaAESGCMMessage* message_out) {
    if (!buffer || !message_out) {
        set_aes_error("NULL pointer in orca_aes_gcm_message_deserialize");
        return -1;
    }
    
    if (buffer_len < ORCA_AES_GCM_NONCE_LEN + ORCA_AES_GCM_TAG_LEN + 4) {
        set_aes_error("Buffer too short for message");
        return -1;
    }
    
    memset(message_out, 0, sizeof(OrcaAESGCMMessage));
    
    const unsigned char* ptr = buffer;
    memcpy(message_out->nonce.nonce, ptr, ORCA_AES_GCM_NONCE_LEN);
    ptr += ORCA_AES_GCM_NONCE_LEN;
    
    memcpy(message_out->tag.tag, ptr, ORCA_AES_GCM_TAG_LEN);
    ptr += ORCA_AES_GCM_TAG_LEN;
    
    uint32_t ciphertext_len;
    memcpy(&ciphertext_len, ptr, 4);
    message_out->ciphertext_len = ntohl(ciphertext_len);
    ptr += 4;
    
    if (ptr + message_out->ciphertext_len > buffer + buffer_len) {
        set_aes_error("Buffer too short for ciphertext");
        return -1;
    }
    
    message_out->ciphertext = (unsigned char*)malloc(message_out->ciphertext_len);
    if (!message_out->ciphertext) {
        set_aes_error("malloc failed for ciphertext");
        return -1;
    }
    memcpy(message_out->ciphertext, ptr, message_out->ciphertext_len);
    
    message_out->encrypted = true;
    return 0;
}

int orca_aes_gcm_message_to_base64(const OrcaAESGCMMessage* message,
                                   char** b64_out) {
    if (!message || !b64_out) {
        set_aes_error("NULL pointer in orca_aes_gcm_message_to_base64");
        return -1;
    }
    
    unsigned char* buffer;
    size_t buffer_len;
    if (orca_aes_gcm_message_serialize(message, &buffer, &buffer_len) < 0) {
        return -1;
    }
    
    *b64_out = orca_base64_encode(buffer, buffer_len);
    free(buffer);
    
    if (!*b64_out) {
        set_aes_error("Failed to base64 encode message");
        return -1;
    }
    
    return 0;
}

int orca_aes_gcm_message_from_base64(const char* b64,
                                     OrcaAESGCMMessage* message_out) {
    if (!b64 || !message_out) {
        set_aes_error("NULL pointer in orca_aes_gcm_message_from_base64");
        return -1;
    }
    
    int buffer_len;
    unsigned char* buffer = orca_base64_decode(b64, &buffer_len);
    if (!buffer) {
        set_aes_error("Failed to decode base64");
        return -1;
    }
    
    int result = orca_aes_gcm_message_deserialize(buffer, buffer_len, message_out);
    free(buffer);
    
    return result;
}

/* ============================================================================
 * MESSAGE MANAGEMENT
 * ============================================================================ */

void orca_aes_gcm_message_init(OrcaAESGCMMessage* message) {
    if (!message) return;
    memset(message, 0, sizeof(OrcaAESGCMMessage));
}

void orca_aes_gcm_message_free(OrcaAESGCMMessage* message) {
    if (!message) return;
    
    if (message->ciphertext) {
        zeroize(message->ciphertext, message->ciphertext_len);
        free(message->ciphertext);
        message->ciphertext = NULL;
    }
    
    if (message->plaintext) {
        zeroize(message->plaintext, message->plaintext_len);
        free(message->plaintext);
        message->plaintext = NULL;
    }
    
    zeroize(message->key.key, ORCA_AES_GCM_KEY_LEN);
    zeroize(message->nonce.nonce, ORCA_AES_GCM_NONCE_LEN);
    zeroize(message->tag.tag, ORCA_AES_GCM_TAG_LEN);
    
    message->ciphertext_len = 0;
    message->plaintext_len = 0;
    message->encrypted = false;
    message->decrypted = false;
}

int orca_aes_gcm_message_copy(const OrcaAESGCMMessage* src,
                              OrcaAESGCMMessage* dst) {
    if (!src || !dst) {
        set_aes_error("NULL pointer in orca_aes_gcm_message_copy");
        return -1;
    }
    
    memset(dst, 0, sizeof(OrcaAESGCMMessage));
    
    memcpy(dst->key.key, src->key.key, ORCA_AES_GCM_KEY_LEN);
    memcpy(dst->nonce.nonce, src->nonce.nonce, ORCA_AES_GCM_NONCE_LEN);
    memcpy(dst->tag.tag, src->tag.tag, ORCA_AES_GCM_TAG_LEN);
    
    dst->ciphertext_len = src->ciphertext_len;
    dst->plaintext_len = src->plaintext_len;
    dst->encrypted = src->encrypted;
    dst->decrypted = src->decrypted;
    
    if (src->ciphertext && src->ciphertext_len > 0) {
        dst->ciphertext = (unsigned char*)malloc(src->ciphertext_len);
        if (!dst->ciphertext) {
            set_aes_error("malloc failed for ciphertext copy");
            return -1;
        }
        memcpy(dst->ciphertext, src->ciphertext, src->ciphertext_len);
    }
    
    if (src->plaintext && src->plaintext_len > 0) {
        dst->plaintext = (unsigned char*)malloc(src->plaintext_len);
        if (!dst->plaintext) {
            free(dst->ciphertext);
            set_aes_error("malloc failed for plaintext copy");
            return -1;
        }
        memcpy(dst->plaintext, src->plaintext, src->plaintext_len);
    }
    
    return 0;
}

void orca_aes_gcm_message_clear(OrcaAESGCMMessage* message) {
    orca_aes_gcm_message_free(message);
}

/* ============================================================================
 * KEY EXCHANGE INTEGRATION
 * ============================================================================ */

int orca_aes_gcm_derive_key_from_shared_secret(const unsigned char* shared_secret,
                                               const unsigned char* salt,
                                               size_t salt_len,
                                               const unsigned char* info,
                                               size_t info_len,
                                               unsigned char* key_out) {
    if (!shared_secret || !key_out) {
        set_aes_error("NULL pointer in orca_aes_gcm_derive_key_from_shared_secret");
        return -1;
    }
    
    openssl_aes_init();
    
    // Use HKDF to derive AES key from shared secret
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) {
        set_aes_error("Failed to create HKDF context");
        return -1;
    }
    
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        set_aes_error("Failed to init HKDF");
        return -1;
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        set_aes_error("Failed to set HKDF digest");
        return -1;
    }
    
    if (salt && salt_len > 0) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            set_aes_error("Failed to set HKDF salt");
            return -1;
        }
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, shared_secret, ORCA_AES_GCM_KEY_LEN) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        set_aes_error("Failed to set HKDF key");
        return -1;
    }
    
    if (info && info_len > 0) {
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, info_len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            set_aes_error("Failed to set HKDF info");
            return -1;
        }
    }
    
    size_t key_len = ORCA_AES_GCM_KEY_LEN;
    if (EVP_PKEY_derive(ctx, key_out, &key_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        set_aes_error("Failed to derive AES key");
        return -1;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    if (key_len != ORCA_AES_GCM_KEY_LEN) {
        set_aes_error("Unexpected AES key length");
        return -1;
    }
    
    return 0;
}

int orca_aes_gcm_derive_key_from_shared_secret_hex(const char* shared_secret_hex,
                                                   const char* salt_hex,
                                                   const unsigned char* info,
                                                   size_t info_len,
                                                   char* key_hex_out) {
    if (!shared_secret_hex || !key_hex_out) {
        set_aes_error("NULL pointer in orca_aes_gcm_derive_key_from_shared_secret_hex");
        return -1;
    }
    
    unsigned char shared_secret[ORCA_AES_GCM_KEY_LEN];
    if (orca_hex_to_bytes(shared_secret_hex, shared_secret, ORCA_AES_GCM_KEY_LEN) < 0) {
        set_aes_error("Invalid shared secret hex");
        return -1;
    }
    
    unsigned char salt[16];
    unsigned char* salt_ptr = NULL;
    size_t salt_len = 0;
    
    if (salt_hex) {
        salt_len = 16;
        if (orca_hex_to_bytes(salt_hex, salt, salt_len) < 0) {
            zeroize(shared_secret, ORCA_AES_GCM_KEY_LEN);
            set_aes_error("Invalid salt hex");
            return -1;
        }
        salt_ptr = salt;
    }
    
    unsigned char aes_key[ORCA_AES_GCM_KEY_LEN];
    if (orca_aes_gcm_derive_key_from_shared_secret(shared_secret, salt_ptr, salt_len,
                                                   info, info_len, aes_key) < 0) {
        zeroize(shared_secret, ORCA_AES_GCM_KEY_LEN);
        zeroize(aes_key, ORCA_AES_GCM_KEY_LEN);
        return -1;
    }
    
    orca_bytes_to_hex(aes_key, ORCA_AES_GCM_KEY_LEN, key_hex_out);
    
    zeroize(shared_secret, ORCA_AES_GCM_KEY_LEN);
    zeroize(aes_key, ORCA_AES_GCM_KEY_LEN);
    
    return 0;
}

/* ============================================================================
 * DEBUG FUNCTIONS
 * ============================================================================ */

void orca_aes_gcm_debug_print_key(const unsigned char* key, const char* label) {
    if (!key) return;
    
    char hex[65];
    if (label) printf("[AES-GCM DEBUG] %s\n", label);
    printf("  Key: %s\n", orca_bytes_to_hex(key, ORCA_AES_GCM_KEY_LEN, hex));
}

void orca_aes_gcm_debug_print_nonce(const unsigned char* nonce, const char* label) {
    if (!nonce) return;
    
    char hex[25];
    if (label) printf("[AES-GCM DEBUG] %s\n", label);
    printf("  Nonce: %s\n", orca_bytes_to_hex(nonce, ORCA_AES_GCM_NONCE_LEN, hex));
}

void orca_aes_gcm_debug_print_tag(const unsigned char* tag, const char* label) {
    if (!tag) return;
    
    char hex[33];
    if (label) printf("[AES-GCM DEBUG] %s\n", label);
    printf("  Tag: %s\n", orca_bytes_to_hex(tag, ORCA_AES_GCM_TAG_LEN, hex));
}

void orca_aes_gcm_debug_print_message(const OrcaAESGCMMessage* message,
                                      const char* label) {
    if (!message) return;
    
    if (label) printf("[AES-GCM DEBUG] %s\n", label);
    printf("  Encrypted: %s\n", message->encrypted ? "YES" : "NO");
    printf("  Decrypted: %s\n", message->decrypted ? "YES" : "NO");
    printf("  Plaintext Length: %zu\n", message->plaintext_len);
    printf("  Ciphertext Length: %zu\n", message->ciphertext_len);
    
    orca_aes_gcm_debug_print_key(message->key.key, "Key");
    orca_aes_gcm_debug_print_nonce(message->nonce.nonce, "Nonce");
    orca_aes_gcm_debug_print_tag(message->tag.tag, "Tag");
    
    if (message->plaintext && message->plaintext_len > 0) {
        printf("  Plaintext: %.*s\n", (int)message->plaintext_len, message->plaintext);
    }
}

/* ============================================================================
 * TEST FUNCTIONS
 * ============================================================================ */

int orca_aes_gcm_test_self(void) {
    printf("[AES-GCM TEST] Running self-test...\n");
    
    // Generate key and nonce
    unsigned char key[ORCA_AES_GCM_KEY_LEN];
    unsigned char nonce[ORCA_AES_GCM_NONCE_LEN];
    
    if (orca_aes_gcm_key_generate(key) < 0) {
        printf("[AES-GCM TEST] FAIL: Key generation\n");
        return -1;
    }
    
    if (orca_aes_gcm_nonce_generate(nonce) < 0) {
        printf("[AES-GCM TEST] FAIL: Nonce generation\n");
        zeroize(key, ORCA_AES_GCM_KEY_LEN);
        return -1;
    }
    
    // Test data
    const char* plaintext = "Hello, Orcashi! This is a test message for AES-GCM encryption.";
    size_t plaintext_len = strlen(plaintext);
    
    // Encrypt
    unsigned char tag[ORCA_AES_GCM_TAG_LEN];
    unsigned char* ciphertext;
    size_t ciphertext_len;
    
    if (orca_aes_gcm_encrypt((const unsigned char*)plaintext, plaintext_len,
                             key, nonce, tag, &ciphertext, &ciphertext_len) < 0) {
        printf("[AES-GCM TEST] FAIL: Encryption\n");
        zeroize(key, ORCA_AES_GCM_KEY_LEN);
        zeroize(nonce, ORCA_AES_GCM_NONCE_LEN);
        return -1;
    }
    
    // Decrypt
    unsigned char* decrypted;
    size_t decrypted_len;
    
    if (orca_aes_gcm_decrypt(ciphertext, ciphertext_len,
                             key, nonce, tag, &decrypted, &decrypted_len) < 0) {
        printf("[AES-GCM TEST] FAIL: Decryption\n");
        free(ciphertext);
        zeroize(key, ORCA_AES_GCM_KEY_LEN);
        zeroize(nonce, ORCA_AES_GCM_NONCE_LEN);
        return -1;
    }
    
    // Verify
    if (decrypted_len != plaintext_len ||
        memcmp(decrypted, plaintext, plaintext_len) != 0) {
        printf("[AES-GCM TEST] FAIL: Plaintext mismatch\n");
        free(ciphertext);
        free(decrypted);
        zeroize(key, ORCA_AES_GCM_KEY_LEN);
        zeroize(nonce, ORCA_AES_GCM_NONCE_LEN);
        return -1;
    }
    
    printf("[AES-GCM TEST] SUCCESS: Encryption and decryption work!\n");
    
    free(ciphertext);
    free(decrypted);
    zeroize(key, ORCA_AES_GCM_KEY_LEN);
    zeroize(nonce, ORCA_AES_GCM_NONCE_LEN);
    
    // Test message API
    printf("[AES-GCM TEST] Testing message API...\n");
    
    OrcaAESGCMMessage msg;
    orca_aes_gcm_message_init(&msg);
    
    if (orca_aes_gcm_encrypt_message((const unsigned char*)plaintext, plaintext_len,
                                     key, &msg) < 0) {
        printf("[AES-GCM TEST] FAIL: Message encryption\n");
        return -1;
    }
    
    unsigned char* msg_decrypted;
    size_t msg_decrypted_len;
    
    if (orca_aes_gcm_decrypt_message(&msg, key, &msg_decrypted, &msg_decrypted_len) < 0) {
        printf("[AES-GCM TEST] FAIL: Message decryption\n");
        orca_aes_gcm_message_free(&msg);
        return -1;
    }
    
    if (msg_decrypted_len != plaintext_len ||
        memcmp(msg_decrypted, plaintext, plaintext_len) != 0) {
        printf("[AES-GCM TEST] FAIL: Message plaintext mismatch\n");
        free(msg_decrypted);
        orca_aes_gcm_message_free(&msg);
        return -1;
    }
    
    free(msg_decrypted);
    orca_aes_gcm_message_free(&msg);
    
    printf("[AES-GCM TEST] SUCCESS: All tests passed!\n");
    return 0;
}

int orca_aes_gcm_test_vectors(void) {
    printf("[AES-GCM TEST] Running vector tests...\n");
    
    // RFC 5116 test vector for AES-256-GCM
    // Key: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    // Nonce: 000102030405060708090a0b
    // Plaintext: 54657374206d657373616765
    // Expected Ciphertext: 5b175a7ef4f12ca13e54b4b9e20fbf31cbbd4b4a
    // Expected Tag: 99e5411f8b90c8c3b4c2c34d8f2f0b8a
    
    const char* key_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const char* nonce_hex = "000102030405060708090a0b";
    const char* plaintext = "Test message";
    const char* expected_ciphertext_hex = "5b175a7ef4f12ca13e54b4b9e20fbf31cbbd4b4a";
    const char* expected_tag_hex = "99e5411f8b90c8c3b4c2c34d8f2f0b8a";
    
    unsigned char key[ORCA_AES_GCM_KEY_LEN];
    unsigned char nonce[ORCA_AES_GCM_NONCE_LEN];
    unsigned char expected_ciphertext[32];
    unsigned char expected_tag[ORCA_AES_GCM_TAG_LEN];
    unsigned char ciphertext[32];
    unsigned char tag[ORCA_AES_GCM_TAG_LEN];
    unsigned char decrypted[32];
    size_t ciphertext_len, decrypted_len;
    unsigned char* ciphertext_ptr;
    
    orca_hex_to_bytes(key_hex, key, ORCA_AES_GCM_KEY_LEN);
    orca_hex_to_bytes(nonce_hex, nonce, ORCA_AES_GCM_NONCE_LEN);
    
    // Encrypt
    if (orca_aes_gcm_encrypt((const unsigned char*)plaintext, strlen(plaintext),
                             key, nonce, tag, &ciphertext_ptr, &ciphertext_len) < 0) {
        printf("[AES-GCM TEST] FAIL: Vector encryption\n");
        return -1;
    }
    
    // Verify ciphertext
    char ciphertext_hex[65];
    orca_bytes_to_hex(ciphertext_ptr, ciphertext_len, ciphertext_hex);
    
    if (strcmp(ciphertext_hex, expected_ciphertext_hex) != 0) {
        printf("[AES-GCM TEST] FAIL: Ciphertext mismatch\n");
        printf("  Expected: %s\n", expected_ciphertext_hex);
        printf("  Got:      %s\n", ciphertext_hex);
        free(ciphertext_ptr);
        return -1;
    }
    
    // Verify tag
    char tag_hex[33];
    orca_bytes_to_hex(tag, ORCA_AES_GCM_TAG_LEN, tag_hex);
    
    if (strcmp(tag_hex, expected_tag_hex) != 0) {
        printf("[AES-GCM TEST] FAIL: Tag mismatch\n");
        printf("  Expected: %s\n", expected_tag_hex);
        printf("  Got:      %s\n", tag_hex);
        free(ciphertext_ptr);
        return -1;
    }
    
    // Decrypt
    if (orca_aes_gcm_decrypt(ciphertext_ptr, ciphertext_len,
                             key, nonce, tag, &decrypted, &decrypted_len) < 0) {
        printf("[AES-GCM TEST] FAIL: Vector decryption\n");
        free(ciphertext_ptr);
        return -1;
    }
    
    free(ciphertext_ptr);
    
    if (decrypted_len != strlen(plaintext) ||
        memcmp(decrypted, plaintext, strlen(plaintext)) != 0) {
        printf("[AES-GCM TEST] FAIL: Decrypted text mismatch\n");
        free(decrypted);
        return -1;
    }
    
    free(decrypted);
    printf("[AES-GCM TEST] SUCCESS: Vector tests passed!\n");
    return 0;
}
