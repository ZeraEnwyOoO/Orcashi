 // aes_gcm.c - Full implementation with OpenSSL 3.0 compatibility
#include "aes_gcm.h"
#include "orca_crypto.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

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
    
    for (int i = ORCA_AES_GCM_NONCE_LEN - 1; i >= 0; i--) {
        nonce[i]++;
        if (nonce[i] != 0) break;
    }
    
    return 0;
}

void orca_aes_gcm_nonce_zeroize(unsigned char* nonce) {
    if (nonce) {
        zeroize(nonce, ORCA_AES_GCM_NONCE_LEN);
    }
}

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

/* ============================================================================
 * KEY EXCHANGE INTEGRATION - FIXED for OpenSSL 3.0
 * Uses EVP_KDF_CTX API which is compatible with both 1.1.1 and 3.0
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
    
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* OpenSSL 3.0 - Use EVP_KDF API */
    EVP_KDF_CTX* kctx = NULL;
    EVP_KDF* kdf = NULL;
    OSSL_PARAM params[5];
    int param_idx = 0;
    
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        set_aes_error("Failed to fetch HKDF");
        return -1;
    }
    
    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        EVP_KDF_free(kdf);
        set_aes_error("Failed to create KDF context");
        return -1;
    }
    
    params[param_idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                            (void*)shared_secret,
                                                            ORCA_AES_GCM_KEY_LEN);
    params[param_idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                           "sha256", 0);
    
    if (salt && salt_len > 0) {
        params[param_idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                                (void*)salt,
                                                                salt_len);
    }
    
    if (info && info_len > 0) {
        params[param_idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                                (void*)info,
                                                                info_len);
    }
    
    params[param_idx] = OSSL_PARAM_construct_end();
    
    if (EVP_KDF_derive(kctx, key_out, ORCA_AES_GCM_KEY_LEN, params) <= 0) {
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
        set_aes_error("Failed to derive AES key");
        return -1;
    }
    
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    
#else
    /* OpenSSL 1.1.1 - Use EVP_PKEY_CTX HKDF API */
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
#endif
    
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
 * MESSAGE MANAGEMENT FUNCTIONS
 * ============================================================================ */

void orca_aes_gcm_message_init(OrcaAESGCMMessage* message) {
    if (message) {
        memset(message, 0, sizeof(OrcaAESGCMMessage));
    }
}

void orca_aes_gcm_message_free(OrcaAESGCMMessage* message) {
    if (message) {
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
        message->ciphertext_len = 0;
        message->plaintext_len = 0;
        message->encrypted = false;
        message->decrypted = false;
    }
}

void orca_aes_gcm_message_clear(OrcaAESGCMMessage* message) {
    orca_aes_gcm_message_free(message);
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
    
    if (orca_aes_gcm_nonce_generate(message_out->nonce.nonce) < 0) {
        set_aes_error("Failed to generate nonce");
        return -1;
    }
    
    unsigned char* ciphertext;
    size_t ciphertext_len;
    
    if (orca_aes_gcm_encrypt(plaintext, plaintext_len, key,
                             message_out->nonce.nonce,
                             message_out->tag.tag,
                             &ciphertext, &ciphertext_len) < 0) {
        return -1;
    }
    
    message_out->ciphertext = ciphertext;
    message_out->ciphertext_len = ciphertext_len;
    message_out->encrypted = true;
    
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
                                key, message->nonce.nonce, message->tag.tag,
                                plaintext_out, plaintext_len);
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
    printf("  Encrypted: %s\n", message->encrypted ? "true" : "false");
    printf("  Decrypted: %s\n", message->decrypted ? "true" : "false");
    printf("  Ciphertext length: %zu\n", message->ciphertext_len);
    printf("  Plaintext length: %zu\n", message->plaintext_len);
    orca_aes_gcm_debug_print_nonce(message->nonce.nonce, "Nonce");
    orca_aes_gcm_debug_print_tag(message->tag.tag, "Tag");
}

/* ============================================================================
 * TEST FUNCTIONS
 * ============================================================================ */

int orca_aes_gcm_test_self(void) {
    printf("[AES-GCM TEST] Running self-test...\n");
    
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
    
    const char* plaintext = "Hello, Orcashi! This is a test message for AES-GCM encryption.";
    size_t plaintext_len = strlen(plaintext);
    
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
    
    return 0;
}

int orca_aes_gcm_test_vectors(void) {
    printf("[AES-GCM TEST] Running vector test...\n");
    
    /* NIST test vector */
    const unsigned char key[16] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };
    const unsigned char nonce[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
    };
    const unsigned char expected_ciphertext[16] = {
        0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
        0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c
    };
    const unsigned char expected_tag[16] = {
        0x4c, 0x4d, 0xfb, 0xc0, 0xd9, 0x2d, 0xe7, 0x4d,
        0x54, 0xfa, 0x1f, 0x89, 0x4c, 0x04, 0xb1, 0x5c
    };
    
    unsigned char tag[ORCA_AES_GCM_TAG_LEN];
    unsigned char* ciphertext;
    size_t ciphertext_len;
    
    if (orca_aes_gcm_encrypt((const unsigned char*)"", 0,
                             key, nonce, tag, &ciphertext, &ciphertext_len) < 0) {
        printf("[AES-GCM TEST] FAIL: Vector encryption\n");
        return -1;
    }
    
    if (ciphertext_len != 0) {
        printf("[AES-GCM TEST] FAIL: Ciphertext length mismatch\n");
        free(ciphertext);
        return -1;
    }
    
    if (memcmp(tag, expected_tag, ORCA_AES_GCM_TAG_LEN) != 0) {
        printf("[AES-GCM TEST] FAIL: Tag mismatch\n");
        free(ciphertext);
        return -1;
    }
    
    free(ciphertext);
    printf("[AES-GCM TEST] SUCCESS: Vector test passed!\n");
    return 0;
}
