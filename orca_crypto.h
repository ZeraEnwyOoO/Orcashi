#ifndef ORCA_CRYPTO_H
#define ORCA_CRYPTO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * ORCA CRYPTO - Core Cryptographic Functions for Orcashi
 * 
 * This module provides all cryptographic primitives needed for secure P2P:
 *   - RSA 2048-bit keypair generation
 *   - SHA256 hashing
 *   - Base64 encoding/decoding
 *   - RSA signing and verification
 *   - AES-256-CBC encryption/decryption (for private key storage)
 *   - AES-256-GCM encryption/decryption (for message encryption)
 *   - X25519 ECDH key exchange
 * ============================================================================ */

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

#define ORCA_RSA_KEY_BITS 2048
#define ORCA_RSA_KEY_LEN 4096
#define ORCA_SHA256_LEN 32
#define ORCA_AES_KEY_LEN 32      /* 256-bit */
#define ORCA_AES_IV_LEN 16       /* 128-bit */
#define ORCA_AES_GCM_TAG_LEN 16  /* 128-bit */
#define ORCA_X25519_KEY_LEN 32
#define ORCA_SIGNATURE_LEN 64    /* Ed25519 or RSA-2048 signature */
#define ORCA_ID_LEN 64
#define ORCA_NAME_LEN 128
#define ORCA_ROLE_LEN 32
#define ORCA_PUBKEY_LEN 4096
#define ORCA_PRIVKEY_LEN 4096
#define ORCA_ENCRYPTED_LEN 4096

/* ============================================================================
 * DATA TYPES
 * ============================================================================ */

typedef struct {
    unsigned char data[ORCA_SHA256_LEN];
} OrcaHash;

typedef struct {
    unsigned char key[ORCA_AES_KEY_LEN];
} OrcaAESKey;

typedef struct {
    unsigned char iv[ORCA_AES_IV_LEN];
} OrcaIV;

typedef struct {
    unsigned char key[ORCA_X25519_KEY_LEN];
} OrcaX25519Key;

typedef struct {
    OrcaX25519Key public_key;
    OrcaX25519Key private_key;
} OrcaX25519Keypair;

typedef struct {
    unsigned char data[ORCA_RSA_KEY_LEN];
    int len;
} OrcaRSAKey;

typedef struct {
    unsigned char data[ORCA_SIGNATURE_LEN];
    int len;
} OrcaSignature;

/* ============================================================================
 * HASH FUNCTIONS (SHA256)
 * ============================================================================ */

/**
 * orca_hash - Compute SHA256 hash of data
 * @param data: Input data
 * @param len: Length of input data
 * @param out: Output hash (must be 32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_hash(const unsigned char* data, size_t len, unsigned char* out);

/**
 * orca_hash_string - Compute SHA256 hash of a string
 * @param str: Input string
 * @param out: Output hash (must be 32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_hash_string(const char* str, unsigned char* out);

/**
 * orca_hash_to_hex - Convert hash to hex string
 * @param hash: Input hash (32 bytes)
 * @param out: Output hex string (must be 65 bytes)
 * @return: Pointer to out
 */
char* orca_hash_to_hex(const unsigned char* hash, char* out);

/**
 * orca_hash_to_id - Convert hash to human-readable ID
 * @param hash: Input hash (32 bytes)
 * @param prefix: Optional prefix (e.g., "ORCA-")
 * @param out: Output ID string (must be 64 bytes)
 * @return: Pointer to out
 */
char* orca_hash_to_id(const unsigned char* hash, const char* prefix, char* out);

/* ============================================================================
 * BASE64 FUNCTIONS
 * ============================================================================ */

/**
 * orca_base64_encode - Encode binary data to base64
 * @param data: Input binary data
 * @param len: Length of input data
 * @return: Base64 encoded string (must be freed by caller)
 */
char* orca_base64_encode(const unsigned char* data, int len);

/**
 * orca_base64_decode - Decode base64 string to binary
 * @param data: Input base64 string
 * @param out_len: Output length (optional)
 * @return: Binary data (must be freed by caller)
 */
unsigned char* orca_base64_decode(const char* data, int* out_len);

/* ============================================================================
 * RSA FUNCTIONS
 * ============================================================================ */

/**
 * orca_rsa_generate_keypair - Generate RSA 2048-bit keypair
 * @param public_key_out: Output public key (PEM format, must be freed)
 * @param private_key_out: Output private key (PEM format, must be freed)
 * @return: 0 on success, -1 on failure
 */
int orca_rsa_generate_keypair(char** public_key_out, char** private_key_out);

/**
 * orca_rsa_sign - Sign data with RSA private key
 * @param data: Input data to sign
 * @param data_len: Length of input data
 * @param private_key_pem: Private key in PEM format
 * @param signature_out: Output signature (base64 encoded, must be freed)
 * @return: 0 on success, -1 on failure
 */
int orca_rsa_sign(const unsigned char* data, size_t data_len,
                  const char* private_key_pem, char** signature_out);

/**
 * orca_rsa_sign_string - Sign a string with RSA private key
 * @param str: Input string to sign
 * @param private_key_pem: Private key in PEM format
 * @param signature_out: Output signature (base64 encoded, must be freed)
 * @return: 0 on success, -1 on failure
 */
int orca_rsa_sign_string(const char* str, const char* private_key_pem,
                         char** signature_out);

/**
 * orca_rsa_verify - Verify RSA signature
 * @param data: Input data that was signed
 * @param data_len: Length of input data
 * @param signature: Base64 encoded signature
 * @param public_key_pem: Public key in PEM format
 * @return: true if signature is valid, false otherwise
 */
bool orca_rsa_verify(const unsigned char* data, size_t data_len,
                     const char* signature, const char* public_key_pem);

/**
 * orca_rsa_verify_string - Verify RSA signature of a string
 * @param str: Input string that was signed
 * @param signature: Base64 encoded signature
 * @param public_key_pem: Public key in PEM format
 * @return: true if signature is valid, false otherwise
 */
bool orca_rsa_verify_string(const char* str, const char* signature,
                            const char* public_key_pem);

/**
 * orca_rsa_public_key_from_pem - Extract public key from PEM
 * @param pem: Public key in PEM format
 * @param out: Output buffer for raw key
 * @param out_len: Output length
 * @return: 0 on success, -1 on failure
 */
int orca_rsa_public_key_from_pem(const char* pem, unsigned char* out, int* out_len);

/* ============================================================================
 * AES-256-CBC FUNCTIONS (For private key storage)
 * ============================================================================ */

/**
 * orca_aes_cbc_encrypt - Encrypt data with AES-256-CBC
 * @param data: Input plaintext
 * @param data_len: Length of input data
 * @param key: 32-byte AES key
 * @param iv_out: Output IV (16 bytes, must be provided)
 * @param ciphertext_out: Output ciphertext (must be freed by caller)
 * @param ciphertext_len: Output length
 * @return: 0 on success, -1 on failure
 */
int orca_aes_cbc_encrypt(const unsigned char* data, size_t data_len,
                         const unsigned char* key,
                         unsigned char* iv_out,
                         unsigned char** ciphertext_out,
                         size_t* ciphertext_len);

/**
 * orca_aes_cbc_decrypt - Decrypt data with AES-256-CBC
 * @param ciphertext: Input ciphertext
 * @param ciphertext_len: Length of ciphertext
 * @param key: 32-byte AES key
 * @param iv: 16-byte IV
 * @param plaintext_out: Output plaintext (must be freed by caller)
 * @param plaintext_len: Output length
 * @return: 0 on success, -1 on failure
 */
int orca_aes_cbc_decrypt(const unsigned char* ciphertext, size_t ciphertext_len,
                         const unsigned char* key,
                         const unsigned char* iv,
                         unsigned char** plaintext_out,
                         size_t* plaintext_len);

/**
 * orca_aes_cbc_encrypt_string - Encrypt a string with AES-256-CBC
 * @param str: Input string
 * @param key_hex: 64-character hex key (32 bytes)
 * @param iv_hex_out: Output hex IV (must be 33 bytes)
 * @param ciphertext_b64_out: Output base64 ciphertext (must be freed)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_cbc_encrypt_string(const char* str, const char* key_hex,
                                char* iv_hex_out, char** ciphertext_b64_out);

/**
 * orca_aes_cbc_decrypt_string - Decrypt a string with AES-256-CBC
 * @param ciphertext_b64: Base64 encoded ciphertext
 * @param iv_hex: 32-character hex IV (16 bytes)
 * @param key_hex: 64-character hex key (32 bytes)
 * @param plaintext_out: Output plaintext (must be freed by caller)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_cbc_decrypt_string(const char* ciphertext_b64, const char* iv_hex,
                                const char* key_hex, char** plaintext_out);

/* ============================================================================
 * AES-256-GCM FUNCTIONS (For message encryption)
 * ============================================================================ */

/**
 * orca_aes_gcm_encrypt - Encrypt data with AES-256-GCM
 * @param data: Input plaintext
 * @param data_len: Length of input data
 * @param key: 32-byte AES key
 * @param nonce: 12-byte nonce (must be provided)
 * @param tag_out: Output authentication tag (16 bytes)
 * @param ciphertext_out: Output ciphertext (must be freed by caller)
 * @param ciphertext_len: Output length
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_encrypt(const unsigned char* data, size_t data_len,
                         const unsigned char* key,
                         unsigned char* nonce,
                         unsigned char* tag_out,
                         unsigned char** ciphertext_out,
                         size_t* ciphertext_len);

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
 * orca_aes_gcm_encrypt_string - Encrypt a string with AES-256-GCM
 * @param str: Input string
 * @param key_hex: 64-character hex key (32 bytes)
 * @param nonce_hex_out: Output hex nonce (must be 25 bytes)
 * @param tag_hex_out: Output hex tag (must be 33 bytes)
 * @param ciphertext_b64_out: Output base64 ciphertext (must be freed)
 * @return: 0 on success, -1 on failure
 */
int orca_aes_gcm_encrypt_string(const char* str, const char* key_hex,
                                char* nonce_hex_out, char* tag_hex_out,
                                char** ciphertext_b64_out);

/**
 * orca_aes_gcm_decrypt_string - Decrypt a string with AES-256-GCM
 * @param ciphertext_b64: Base64 encoded ciphertext
 * @param nonce_hex: 24-character hex nonce (12 bytes)
 * @param tag_hex: 32-character hex tag (16 bytes)
 * @param key_hex: 64-character hex key (32 bytes)
 * @param plaintext_out: Output plaintext (must be freed by caller)
 * @return: 0 on success, -1 on failure (authentication failure)
 */
int orca_aes_gcm_decrypt_string(const char* ciphertext_b64, const char* nonce_hex,
                                const char* tag_hex, const char* key_hex,
                                char** plaintext_out);

/* ============================================================================
 * X25519 ECDH FUNCTIONS (Key Exchange)
 * ============================================================================ */

/**
 * orca_x25519_generate_keypair - Generate X25519 keypair
 * @param public_key_out: Output public key (32 bytes)
 * @param private_key_out: Output private key (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_x25519_generate_keypair(unsigned char* public_key_out,
                                 unsigned char* private_key_out);

/**
 * orca_x25519_compute_shared_secret - Compute shared secret
 * @param private_key: Private key (32 bytes)
 * @param peer_public_key: Peer public key (32 bytes)
 * @param shared_secret_out: Output shared secret (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_x25519_compute_shared_secret(const unsigned char* private_key,
                                      const unsigned char* peer_public_key,
                                      unsigned char* shared_secret_out);

/**
 * orca_x25519_public_key_to_hex - Convert X25519 public key to hex
 * @param public_key: 32-byte public key
 * @param out: Output hex string (must be 65 bytes)
 * @return: Pointer to out
 */
char* orca_x25519_public_key_to_hex(const unsigned char* public_key, char* out);

/**
 * orca_x25519_hex_to_public_key - Convert hex to X25519 public key
 * @param hex: 64-character hex string
 * @param public_key_out: Output public key (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_x25519_hex_to_public_key(const char* hex, unsigned char* public_key_out);

/* ============================================================================
 * DERIVED KEY FUNCTIONS (PBKDF2)
 * ============================================================================ */

/**
 * orca_derive_key_from_passcode - Derive AES key from passcode (PBKDF2)
 * @param passcode: User passcode
 * @param salt: Salt (16 bytes recommended)
 * @param salt_len: Length of salt
 * @param iterations: Number of iterations (100000 recommended)
 * @param key_out: Output key (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_derive_key_from_passcode(const char* passcode,
                                  const unsigned char* salt,
                                  int salt_len,
                                  int iterations,
                                  unsigned char* key_out);

/**
 * orca_derive_key_from_passcode_hex - Derive key and return as hex
 * @param passcode: User passcode
 * @param salt_hex: Hex encoded salt
 * @param iterations: Number of iterations
 * @param key_hex_out: Output hex key (must be 65 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_derive_key_from_passcode_hex(const char* passcode,
                                      const char* salt_hex,
                                      int iterations,
                                      char* key_hex_out);

/**
 * orca_generate_salt - Generate random salt
 * @param salt_out: Output salt (16 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_generate_salt(unsigned char* salt_out);

/**
 * orca_generate_salt_hex - Generate random salt as hex
 * @param salt_hex_out: Output hex salt (must be 33 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_generate_salt_hex(char* salt_hex_out);

/* ============================================================================
 * UTILITY FUNCTIONS
 * ============================================================================ */

/**
 * orca_random_bytes - Generate cryptographically random bytes
 * @param buf: Output buffer
 * @param len: Number of bytes to generate
 * @return: 0 on success, -1 on failure
 */
int orca_random_bytes(unsigned char* buf, size_t len);

/**
 * orca_hex_to_bytes - Convert hex string to bytes
 * @param hex: Input hex string
 * @param bytes_out: Output bytes
 * @param bytes_len: Length of output buffer
 * @return: 0 on success, -1 on failure
 */
int orca_hex_to_bytes(const char* hex, unsigned char* bytes_out, size_t bytes_len);

/**
 * orca_bytes_to_hex - Convert bytes to hex string
 * @param bytes: Input bytes
 * @param bytes_len: Length of input bytes
 * @param hex_out: Output hex string (must be 2*bytes_len + 1)
 * @return: Pointer to hex_out
 */
char* orca_bytes_to_hex(const unsigned char* bytes, size_t bytes_len, char* hex_out);

/**
 * orca_init_crypto - Initialize OpenSSL crypto library
 * @return: 0 on success, -1 on failure
 */
int orca_init_crypto(void);

/**
 * orca_cleanup_crypto - Cleanup OpenSSL crypto library
 */
void orca_cleanup_crypto(void);

/* ============================================================================
 * ERROR HANDLING
 * ============================================================================ */

/**
 * orca_get_last_error - Get last error string
 * @return: Error string (must not be freed)
 */
const char* orca_get_last_error(void);

/**
 * orca_clear_error - Clear last error
 */
void orca_clear_error(void);

#ifdef __cplusplus
}
#endif

#endif /* ORCA_CRYPTO_H */
