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

#define ORCA_RSA_KEY_BITS 2048
#define ORCA_RSA_KEY_LEN 4096
#define ORCA_SHA256_LEN 32
#define ORCA_AES_KEY_LEN 32
#define ORCA_AES_IV_LEN 16
#define ORCA_AES_GCM_TAG_LEN 16
#define ORCA_X25519_KEY_LEN 32
#define ORCA_SIGNATURE_LEN 64
#define ORCA_SIG_LEN 512
#define ORCA_ID_LEN 64
#define ORCA_NAME_LEN 128
#define ORCA_ROLE_LEN 32
#define ORCA_PUBKEY_LEN 4096
#define ORCA_PRIVKEY_LEN 4096
#define ORCA_ENCRYPTED_LEN 4096

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

int orca_hash(const unsigned char* data, size_t len, unsigned char* out);
int orca_hash_string(const char* str, unsigned char* out);
char* orca_hash_to_hex(const unsigned char* hash, char* out);
char* orca_hash_to_id(const unsigned char* hash, const char* prefix, char* out);

char* orca_base64_encode(const unsigned char* data, int len);
unsigned char* orca_base64_decode(const char* data, int* out_len);

int orca_rsa_generate_keypair(char** public_key_out, char** private_key_out);
int orca_rsa_sign(const unsigned char* data, size_t data_len,
                  const char* private_key_pem, char** signature_out);
int orca_rsa_sign_string(const char* str, const char* private_key_pem,
                         char** signature_out);
bool orca_rsa_verify(const unsigned char* data, size_t data_len,
                     const char* signature, const char* public_key_pem);
bool orca_rsa_verify_string(const char* str, const char* signature,
                            const char* public_key_pem);
int orca_rsa_public_key_from_pem(const char* pem, unsigned char* out, int* out_len);

int orca_aes_cbc_encrypt(const unsigned char* data, size_t data_len,
                         const unsigned char* key,
                         unsigned char* iv_out,
                         unsigned char** ciphertext_out,
                         size_t* ciphertext_len);
int orca_aes_cbc_decrypt(const unsigned char* ciphertext, size_t ciphertext_len,
                         const unsigned char* key,
                         const unsigned char* iv,
                         unsigned char** plaintext_out,
                         size_t* plaintext_len);
int orca_aes_cbc_encrypt_string(const char* str, const char* key_hex,
                                char* iv_hex_out, char** ciphertext_b64_out);
int orca_aes_cbc_decrypt_string(const char* ciphertext_b64, const char* iv_hex,
                                const char* key_hex, char** plaintext_out);

int orca_x25519_generate_keypair(unsigned char* public_key_out,
                                 unsigned char* private_key_out);
int orca_x25519_compute_shared_secret(const unsigned char* private_key,
                                      const unsigned char* peer_public_key,
                                      unsigned char* shared_secret_out);
char* orca_x25519_public_key_to_hex(const unsigned char* public_key, char* out);
int orca_x25519_hex_to_public_key(const char* hex, unsigned char* public_key_out);

int orca_derive_key_from_passcode(const char* passcode,
                                  const unsigned char* salt,
                                  int salt_len,
                                  int iterations,
                                  unsigned char* key_out);
int orca_derive_key_from_passcode_hex(const char* passcode,
                                      const char* salt_hex,
                                      int iterations,
                                      char* key_hex_out);
int orca_generate_salt(unsigned char* salt_out);
int orca_generate_salt_hex(char* salt_hex_out);

int orca_random_bytes(unsigned char* buf, size_t len);
int orca_hex_to_bytes(const char* hex, unsigned char* bytes_out, size_t bytes_len);
char* orca_bytes_to_hex(const unsigned char* bytes, size_t bytes_len, char* hex_out);
int orca_init_crypto(void);
void orca_cleanup_crypto(void);

const char* orca_get_last_error(void);
void orca_clear_error(void);

#ifdef __cplusplus
}
#endif

#endif
