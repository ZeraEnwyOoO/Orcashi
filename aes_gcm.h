// aes_gcm.h - Header file for AES-256-GCM encryption
#ifndef ORCA_AES_GCM_H
#define ORCA_AES_GCM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

#define ORCA_AES_GCM_KEY_LEN 32          /* 256-bit key */
#define ORCA_AES_GCM_IV_LEN 12           /* 96-bit IV (recommended for GCM) */
#define ORCA_AES_GCM_TAG_LEN 16          /* 128-bit authentication tag */
#define ORCA_AES_GCM_NONCE_LEN 12        /* 96-bit nonce */

/* ============================================================================
 * DATA TYPES
 * ============================================================================ */

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

/**
 * orca_aes_gcm_key_generate - Generate random AES-256-GCM key
 * @param key_out: Output key (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_key_generate(unsigned char* key_out);

/**
 * orca_aes_gcm_key_from_hex - Create key from hex string
 * @param hex: 64-character hex string
 * @param key_out: Output key (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_key_from_hex(const char* hex, unsigned char* key_out);

/**
 * orca_aes_gcm_key_to_hex - Convert key to hex string
 * @param key: 32-byte key
 * @param hex_out: Output buffer (must be 65 bytes)
 * @return: Pointer to hex_out
 */
char* orca_aes_gcm_key_to_hex(const unsigned char* key, char* hex_out);

/**
 * orca_aes_gcm_key_zeroize - Zeroize key (secure erase)
 * @param key: Key to zeroize
 */
void orca_aes_gcm_key_zeroize(unsigned char* key);

/* ============================================================================
 * IV / NONCE MANAGEMENT
 * ============================================================================ */

/**
 * orca_aes_gcm_nonce_generate - Generate random nonce
 * @param nonce_out: Output nonce (12 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_nonce_generate(unsigned char* nonce_out);

/**
 * orca_aes_gcm_nonce_from_hex - Create nonce from hex string
 * @param hex: 24-character hex string
 * @param nonce_out: Output nonce (12 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_nonce_from_hex(const char* hex, unsigned char* nonce_out);

/**
 * orca_aes_gcm_nonce_to_hex - Convert nonce to hex string
 * @param nonce: 12-byte nonce
 * @param hex_out: Output buffer (must be 25 bytes)
 * @return: Pointer to hex_out
 */
char* orca_aes_gcm_nonce_to_hex(const unsigned char* nonce, char* hex_out);

/**
 * orca_aes_gcm_nonce_increment - Increment nonce (for sequence)
 * @param nonce: Nonce to increment
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_nonce_increment(unsigned char* nonce);

/**
 * orca_aes_gcm_nonce_increment_hex - Increment nonce from hex string
 * @param nonce_hex: Hex nonce (in-place, must be 25 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_nonce_increment_hex(char* nonce_hex);

/**
 * orca_aes_gcm_nonce_zeroize - Zeroize nonce
 * @param nonce: Nonce to zeroize
 */
void orca_aes_gcm_nonce_zeroize(unsigned char* nonce);

/* ============================================================================
 * ENCRYPTION
 * ============================================================================ */

/**
 * orca_aes_gcm_encrypt - Encrypt data with AES-256-GCM
 * @param plaintext: Input plaintext
 * @param plaintext_len: Length of plaintext
 * @param key: 32-byte AES key
 * @param nonce: 12-byte nonce (must be unique for each encryption)
 * @param tag_out: Output authentication tag (16 bytes)
 * @param ciphertext_out: Output ciphertext (must be freed by caller)
 * @param ciphertext_len: Output length
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_encrypt(const unsigned char* plaintext, size_t plaintext_len,
                         const unsigned char* key,
                         const unsigned char* nonce,
                         unsigned char* tag_out,
                         unsigned char** ciphertext_out,
                         size_t* ciphertext_len);

/**
 * orca_aes_gcm_encrypt_string - Encrypt a string
 * @param plaintext: Input string
 * @param key_hex: 64-character hex key
 * @param nonce_hex_out: Output hex nonce (must be 25 bytes)
 * @param tag_hex_out: Output hex tag (must be 33 bytes)
 * @param ciphertext_b64_out: Output base64 ciphertext (must be freed)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_encrypt_string(const char* plaintext, const char* key_hex,
                                char* nonce_hex_out, char* tag_hex_out,
                                char** ciphertext_b64_out);

/**
 * orca_aes_gcm_encrypt_message - Encrypt a message with automatic nonce generation
 * @param plaintext: Input plaintext
 * @param plaintext_len: Length of plaintext
 * @param key: 32-byte AES key
 * @param message_out: Output message (contains nonce, tag, ciphertext)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_encrypt_message(const unsigned char* plaintext, size_t plaintext_len,
                                 const unsigned char* key,
                                 OrcaAESGCMMessage* message_out);

/**
 * orca_aes_gcm_encrypt_stream - Encrypt a stream (chunk by chunk)
 * @param key: 32-byte AES key
 * @param nonce: 12-byte nonce (must be unique)
 * @param chunk: Input chunk
 * @param chunk_len: Length of chunk
 * @param ciphertext_out: Output ciphertext (must be freed)
 * @param ciphertext_len: Output length
 * @param is_final: true if this is the last chunk
 * @param tag_out: Output tag (only valid when is_final is true)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_encrypt_stream(const unsigned char* key,
                                const unsigned char* nonce,
                                const unsigned char* chunk, size_t chunk_len,
                                unsigned char** ciphertext_out,
                                size_t* ciphertext_len,
                                bool is_final,
                                unsigned char* tag_out);

/* ============================================================================
 * DECRYPTION
 * ============================================================================ */

/**
 * orca_aes_gcm_decrypt - Decrypt data with AES-256-GCM
 * @param ciphertext: Input ciphertext
 * @param ciphertext_len: Length of ciphertext
 * @param key: 32-byte AES key
 * @param nonce: 12-byte nonce
 * @param tag: 16-byte authentication tag
 * @param plaintext_out: Output plaintext (must be freed by caller)
 * @param plaintext_len: Output length
 * @return: 0 on success, -1 on failure (authentication failure)
 */
int orca_aes_gcm_decrypt(const unsigned char* ciphertext, size_t ciphertext_len,
                         const unsigned char* key,
                         const unsigned char* nonce,
                         const unsigned char* tag,
                         unsigned char** plaintext_out,
                         size_t* plaintext_len);

/**
 * orca_aes_gcm_decrypt_string - Decrypt a string
 * @param ciphertext_b64: Base64 encoded ciphertext
 * @param nonce_hex: 24-character hex nonce
 * @param tag_hex: 32-character hex tag
 * @param key_hex: 64-character hex key
 * @param plaintext_out: Output plaintext (must be freed)
 * @return: 0 on success, -1 on failure (authentication failure)
 */
int orca_aes_gcm_decrypt_string(const char* ciphertext_b64, const char* nonce_hex,
                                const char* tag_hex, const char* key_hex,
                                char** plaintext_out);

/**
 * orca_aes_gcm_decrypt_message - Decrypt a message
 * @param message: Input message (must contain ciphertext, nonce, tag)
 * @param key: 32-byte AES key
 * @param plaintext_out: Output plaintext (must be freed by caller)
 * @param plaintext_len: Output length
 * @return: 0 on success, -1 on failure (authentication failure)
 */
int orca_aes_gcm_decrypt_message(const OrcaAESGCMMessage* message,
                                 const unsigned char* key,
                                 unsigned char** plaintext_out,
                                 size_t* plaintext_len);

/**
 * orca_aes_gcm_decrypt_stream - Decrypt a stream (chunk by chunk)
 * @param key: 32-byte AES key
 * @param nonce: 12-byte nonce
 * @param ciphertext: Input ciphertext
 * @param ciphertext_len: Length of ciphertext
 * @param plaintext_out: Output plaintext (must be freed)
 * @param plaintext_len: Output length
 * @param is_final: true if this is the last chunk
 * @param tag: Authentication tag (only valid when is_final is true)
 * @return: 0 on success, -1 on failure (authentication failure)
 */
int orca_aes_gcm_decrypt_stream(const unsigned char* key,
                                const unsigned char* nonce,
                                const unsigned char* ciphertext, size_t ciphertext_len,
                                unsigned char** plaintext_out,
                                size_t* plaintext_len,
                                bool is_final,
                                const unsigned char* tag);

/* ============================================================================
 * MESSAGE SERIALIZATION
 * ============================================================================ */

/**
 * orca_aes_gcm_message_serialize - Serialize message to buffer
 * @param message: Message to serialize
 * @param buffer_out: Output buffer (must be freed by caller)
 * @param buffer_len: Output length
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_message_serialize(const OrcaAESGCMMessage* message,
                                   unsigned char** buffer_out,
                                   size_t* buffer_len);

/**
 * orca_aes_gcm_message_deserialize - Deserialize message from buffer
 * @param buffer: Input buffer
 * @param buffer_len: Length of buffer
 * @param message_out: Output message (must be freed by caller)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_message_deserialize(const unsigned char* buffer,
                                     size_t buffer_len,
                                     OrcaAESGCMMessage* message_out);

/**
 * orca_aes_gcm_message_to_base64 - Convert message to base64 string
 * @param message: Message to convert
 * @param b64_out: Output base64 string (must be freed by caller)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_message_to_base64(const OrcaAESGCMMessage* message,
                                   char** b64_out);

/**
 * orca_aes_gcm_message_from_base64 - Convert base64 string to message
 * @param b64: Input base64 string
 * @param message_out: Output message (must be freed by caller)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_message_from_base64(const char* b64,
                                     OrcaAESGCMMessage* message_out);

/* ============================================================================
 * MESSAGE MANAGEMENT
 * ============================================================================ */

/**
 * orca_aes_gcm_message_init - Initialize message structure
 * @param message: Message to initialize
 */
void orca_aes_gcm_message_init(OrcaAESGCMMessage* message);

/**
 * orca_aes_gcm_message_free - Free message resources
 * @param message: Message to free
 */
void orca_aes_gcm_message_free(OrcaAESGCMMessage* message);

/**
 * orca_aes_gcm_message_copy - Copy message
 * @param src: Source message
 * @param dst: Destination message (must be initialized)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_message_copy(const OrcaAESGCMMessage* src,
                              OrcaAESGCMMessage* dst);

/**
 * orca_aes_gcm_message_clear - Clear message (zeroize sensitive data)
 * @param message: Message to clear
 */
void orca_aes_gcm_message_clear(OrcaAESGCMMessage* message);

/* ============================================================================
 * KEY EXCHANGE INTEGRATION
 * ============================================================================ */

/**
 * orca_aes_gcm_derive_key_from_shared_secret - Derive AES key from ECDH shared secret
 * @param shared_secret: 32-byte ECDH shared secret
 * @param salt: Optional salt (can be NULL)
 * @param salt_len: Length of salt
 * @param info: Optional context info (can be NULL)
 * @param info_len: Length of info
 * @param key_out: Output AES key (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_derive_key_from_shared_secret(const unsigned char* shared_secret,
                                               const unsigned char* salt,
                                               size_t salt_len,
                                               const unsigned char* info,
                                               size_t info_len,
                                               unsigned char* key_out);

/**
 * orca_aes_gcm_derive_key_from_shared_secret_hex - Derive AES key from hex shared secret
 * @param shared_secret_hex: 64-character hex shared secret
 * @param salt_hex: Optional salt hex (can be NULL)
 * @param info: Optional context info (can be NULL)
 * @param info_len: Length of info
 * @param key_hex_out: Output hex AES key (must be 65 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_derive_key_from_shared_secret_hex(const char* shared_secret_hex,
                                                   const char* salt_hex,
                                                   const unsigned char* info,
                                                   size_t info_len,
                                                   char* key_hex_out);

/* ============================================================================
 * DEBUG FUNCTIONS
 * ============================================================================ */

/**
 * orca_aes_gcm_debug_print_key - Print key for debugging
 * @param key: 32-byte key
 * @param label: Label to print (can be NULL)
 */
void orca_aes_gcm_debug_print_key(const unsigned char* key, const char* label);

/**
 * orca_aes_gcm_debug_print_nonce - Print nonce for debugging
 * @param nonce: 12-byte nonce
 * @param label: Label to print (can be NULL)
 */
void orca_aes_gcm_debug_print_nonce(const unsigned char* nonce, const char* label);

/**
 * orca_aes_gcm_debug_print_tag - Print tag for debugging
 * @param tag: 16-byte tag
 * @param label: Label to print (can be NULL)
 */
void orca_aes_gcm_debug_print_tag(const unsigned char* tag, const char* label);

/**
 * orca_aes_gcm_debug_print_message - Print message for debugging
 * @param message: Message to print
 * @param label: Label to print (can be NULL)
 */
void orca_aes_gcm_debug_print_message(const OrcaAESGCMMessage* message,
                                      const char* label);

/* ============================================================================
 * TEST FUNCTIONS
 * ============================================================================ */

/**
 * orca_aes_gcm_test_self - Self-test AES-GCM implementation
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_test_self(void);

/**
 * orca_aes_gcm_test_vectors - Test with known vectors
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_test_vectors(void);

#ifdef __cplusplus
}
#endif

#endif /* ORCA_AES_GCM_H */
