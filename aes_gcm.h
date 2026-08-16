 #ifndef ORCA_AES_GCM_H
#define ORCA_AES_GCM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ORCA_AES_GCM_KEY_LEN 32
#define ORCA_AES_GCM_IV_LEN 12
#define ORCA_AES_GCM_TAG_LEN 16
#define ORCA_AES_GCM_NONCE_LEN 12

typedef struct {
    unsigned char key[ORCA_AES_GCM_KEY_LEN];
} OrcaAESGCMKey;

typedef struct {
    unsigned char iv[ORCA_AES_GCM_IV_LEN];
} OrcaAESGCMIV;

typedef struct {
    unsigned char nonce[ORCA_AES_GCM_NONCE_LEN];
} OrcaAESGCMNonce;

typedef struct {
    unsigned char tag[ORCA_AES_GCM_TAG_LEN];
} OrcaAESGCMTag;

typedef struct {
    OrcaAESGCMKey key;
    OrcaAESGCMNonce nonce;
    OrcaAESGCMTag tag;
    unsigned char* ciphertext;
    size_t ciphertext_len;
    unsigned char* plaintext;
    size_t plaintext_len;
    bool encrypted;
    bool decrypted;
} OrcaAESGCMMessage;

/* ============================================================================
 * KEY MANAGEMENT
 * ============================================================================ */

int orca_aes_gcm_key_generate(unsigned char* key_out);
int orca_aes_gcm_key_from_hex(const char* hex, unsigned char* key_out);
char* orca_aes_gcm_key_to_hex(const unsigned char* key, char* hex_out);
void orca_aes_gcm_key_zeroize(unsigned char* key);

/* ============================================================================
 * IV / NONCE MANAGEMENT
 * ============================================================================ */

int orca_aes_gcm_nonce_generate(unsigned char* nonce_out);
int orca_aes_gcm_nonce_from_hex(const char* hex, unsigned char* nonce_out);
char* orca_aes_gcm_nonce_to_hex(const unsigned char* nonce, char* hex_out);
int orca_aes_gcm_nonce_increment(unsigned char* nonce);
int orca_aes_gcm_nonce_increment_hex(char* nonce_hex);
void orca_aes_gcm_nonce_zeroize(unsigned char* nonce);

/* ============================================================================
 * ENCRYPTION
 * ============================================================================ */

int orca_aes_gcm_encrypt(const unsigned char* plaintext, size_t plaintext_len,
                         const unsigned char* key,
                         const unsigned char* nonce,
                         unsigned char* tag_out,
                         unsigned char** ciphertext_out,
                         size_t* ciphertext_len);

int orca_aes_gcm_encrypt_string(const char* plaintext, const char* key_hex,
                                char* nonce_hex_out, char* tag_hex_out,
                                char** ciphertext_b64_out);

int orca_aes_gcm_encrypt_message(const unsigned char* plaintext, size_t plaintext_len,
                                 const unsigned char* key,
                                 OrcaAESGCMMessage* message_out);

/* ============================================================================
 * DECRYPTION
 * ============================================================================ */

int orca_aes_gcm_decrypt(const unsigned char* ciphertext, size_t ciphertext_len,
                         const unsigned char* key,
                         const unsigned char* nonce,
                         const unsigned char* tag,
                         unsigned char** plaintext_out,
                         size_t* plaintext_len);

int orca_aes_gcm_decrypt_string(const char* ciphertext_b64, const char* nonce_hex,
                                const char* tag_hex, const char* key_hex,
                                char** plaintext_out);

int orca_aes_gcm_decrypt_message(const OrcaAESGCMMessage* message,
                                 const unsigned char* key,
                                 unsigned char** plaintext_out,
                                 size_t* plaintext_len);

/* ============================================================================
 * MESSAGE SERIALIZATION
 * ============================================================================ */

int orca_aes_gcm_message_serialize(const OrcaAESGCMMessage* message,
                                   unsigned char** buffer_out,
                                   size_t* buffer_len);

int orca_aes_gcm_message_deserialize(const unsigned char* buffer,
                                     size_t buffer_len,
                                     OrcaAESGCMMessage* message_out);

int orca_aes_gcm_message_to_base64(const OrcaAESGCMMessage* message,
                                   char** b64_out);

int orca_aes_gcm_message_from_base64(const char* b64,
                                     OrcaAESGCMMessage* message_out);

/* ============================================================================
 * MESSAGE MANAGEMENT
 * ============================================================================ */

void orca_aes_gcm_message_init(OrcaAESGCMMessage* message);
void orca_aes_gcm_message_free(OrcaAESGCMMessage* message);
int orca_aes_gcm_message_copy(const OrcaAESGCMMessage* src,
                              OrcaAESGCMMessage* dst);
void orca_aes_gcm_message_clear(OrcaAESGCMMessage* message);

/* ============================================================================
 * KEY EXCHANGE INTEGRATION
 * ============================================================================ */

int orca_aes_gcm_derive_key_from_shared_secret(const unsigned char* shared_secret,
                                               const unsigned char* salt,
                                               size_t salt_len,
                                               const unsigned char* info,
                                               size_t info_len,
                                               unsigned char* key_out);

int orca_aes_gcm_derive_key_from_shared_secret_hex(const char* shared_secret_hex,
                                                   const char* salt_hex,
                                                   const unsigned char* info,
                                                   size_t info_len,
                                                   char* key_hex_out);

/* ============================================================================
 * DEBUG FUNCTIONS
 * ============================================================================ */

void orca_aes_gcm_debug_print_key(const unsigned char* key, const char* label);
void orca_aes_gcm_debug_print_nonce(const unsigned char* nonce, const char* label);
void orca_aes_gcm_debug_print_tag(const unsigned char* tag, const char* label);
void orca_aes_gcm_debug_print_message(const OrcaAESGCMMessage* message,
                                      const char* label);

/* ============================================================================
 * TEST FUNCTIONS
 * ============================================================================ */

int orca_aes_gcm_test_self(void);
int orca_aes_gcm_test_vectors(void);

#ifdef __cplusplus
}
#endif

#endif /* ORCA_AES_GCM_H */
