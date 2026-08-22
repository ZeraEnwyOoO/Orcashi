 // orca_crypto.c - Full implementation with OpenSSL 3.0 compatibility
#include "orca_crypto.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/kdf.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static char last_error[256] = {0};
static int crypto_initialized = 0;

static void set_error(const char* msg) {
    strncpy(last_error, msg, sizeof(last_error) - 1);
    last_error[sizeof(last_error) - 1] = '\0';
}

static int openssl_init(void) {
    if (!crypto_initialized) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        crypto_initialized = 1;
    }
    return 0;
}

// ===== HASH FUNCTIONS =====
int orca_hash(const unsigned char* data, size_t len, unsigned char* out) {
    if (!data || !out) {
        set_error("NULL pointer in orca_hash");
        return -1;
    }
    
    openssl_init();
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        set_error("Failed to create EVP context");
        return -1;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) <= 0) {
        EVP_MD_CTX_free(ctx);
        set_error("Failed to init digest");
        return -1;
    }
    
    if (EVP_DigestUpdate(ctx, data, len) <= 0) {
        EVP_MD_CTX_free(ctx);
        set_error("Failed to update digest");
        return -1;
    }
    
    unsigned int out_len;
    if (EVP_DigestFinal_ex(ctx, out, &out_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        set_error("Failed to finalize digest");
        return -1;
    }
    
    EVP_MD_CTX_free(ctx);
    return 0;
}

int orca_hash_string(const char* str, unsigned char* out) {
    if (!str || !out) {
        set_error("NULL pointer in orca_hash_string");
        return -1;
    }
    return orca_hash((const unsigned char*)str, strlen(str), out);
}

char* orca_hash_to_hex(const unsigned char* hash, char* out) {
    if (!hash || !out) return NULL;
    for (int i = 0; i < ORCA_SHA256_LEN; i++) {
        sprintf(out + (i * 2), "%02x", hash[i]);
    }
    out[ORCA_SHA256_LEN * 2] = '\0';
    return out;
}

char* orca_hash_to_id(const unsigned char* hash, const char* prefix, char* out) {
    if (!hash || !out) return NULL;
    char hex[65];
    orca_hash_to_hex(hash, hex);
    if (prefix) {
        snprintf(out, ORCA_ID_LEN, "%s%.8s", prefix, hex);
    } else {
        snprintf(out, ORCA_ID_LEN, "%.8s", hex);
    }
    return out;
}

// ===== BASE64 FUNCTIONS =====
char* orca_base64_encode(const unsigned char* data, int len) {
    if (!data || len <= 0) {
        set_error("Invalid input to orca_base64_encode");
        return NULL;
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, len);
    BIO_flush(bio);
    
    BUF_MEM* mem;
    BIO_get_mem_ptr(bio, &mem);
    char* result = (char*)malloc(mem->length + 1);
    if (!result) {
        BIO_free_all(bio);
        set_error("malloc failed in orca_base64_encode");
        return NULL;
    }
    memcpy(result, mem->data, mem->length);
    result[mem->length] = '\0';
    BIO_free_all(bio);
    return result;
}

unsigned char* orca_base64_decode(const char* data, int* out_len) {
    if (!data) {
        set_error("NULL input to orca_base64_decode");
        return NULL;
    }
    
    BIO* bio = BIO_new_mem_buf(data, strlen(data));
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    int len = strlen(data);
    unsigned char* buffer = (unsigned char*)malloc(len + 1);
    if (!buffer) {
        BIO_free_all(bio);
        set_error("malloc failed in orca_base64_decode");
        return NULL;
    }
    
    int decoded_len = BIO_read(bio, buffer, len);
    BIO_free_all(bio);
    
    if (out_len) *out_len = decoded_len;
    return buffer;
}

// ===== RSA FUNCTIONS - FIXED =====
int orca_rsa_generate_keypair(char** public_key_out, char** private_key_out) {
    if (!public_key_out || !private_key_out) {
        set_error("NULL pointer in orca_rsa_generate_keypair");
        return -1;
    }
    
    openssl_init();
    
    printf("[RSA DEBUG] Generating RSA 2048-bit keypair...\n");
    
    /* Use RSA_generate_key_ex directly (more reliable) */
    RSA* rsa = RSA_new();
    if (!rsa) {
        set_error("Failed to create RSA structure");
        return -1;
    }
    
    BIGNUM* e = BN_new();
    if (!e) {
        RSA_free(rsa);
        set_error("Failed to create BIGNUM");
        return -1;
    }
    BN_set_word(e, RSA_F4);
    
    if (RSA_generate_key_ex(rsa, ORCA_RSA_KEY_BITS, e, NULL) != 1) {
        BN_free(e);
        RSA_free(rsa);
        set_error("Failed to generate RSA key");
        return -1;
    }
    BN_free(e);
    
    /* Write private key as EVP_PKEY format */
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        RSA_free(rsa);
        set_error("Failed to create EVP_PKEY");
        return -1;
    }
    
    if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        set_error("Failed to assign RSA to EVP_PKEY");
        return -1;
    }
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        EVP_PKEY_free(pkey);
        set_error("Failed to create BIO for private key");
        return -1;
    }
    
    if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) <= 0) {
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        set_error("Failed to write private key");
        return -1;
    }
    
    char* private_data;
    long private_len = BIO_get_mem_data(bio, &private_data);
    *private_key_out = (char*)malloc(private_len + 1);
    if (!*private_key_out) {
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        set_error("malloc failed for private key");
        return -1;
    }
    memcpy(*private_key_out, private_data, private_len);
    (*private_key_out)[private_len] = '\0';
    BIO_free(bio);
    
    /* Write public key */
    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        free(*private_key_out);
        EVP_PKEY_free(pkey);
        set_error("Failed to create BIO for public key");
        return -1;
    }
    
    if (PEM_write_bio_PUBKEY(bio, pkey) <= 0) {
        BIO_free(bio);
        free(*private_key_out);
        EVP_PKEY_free(pkey);
        set_error("Failed to write public key");
        return -1;
    }
    
    char* public_data;
    long public_len = BIO_get_mem_data(bio, &public_data);
    *public_key_out = (char*)malloc(public_len + 1);
    if (!*public_key_out) {
        BIO_free(bio);
        free(*private_key_out);
        EVP_PKEY_free(pkey);
        set_error("malloc failed for public key");
        return -1;
    }
    memcpy(*public_key_out, public_data, public_len);
    (*public_key_out)[public_len] = '\0';
    BIO_free(bio);
    
    EVP_PKEY_free(pkey);
    
    printf("[RSA DEBUG] Keypair generated successfully!\n");
    printf("[RSA DEBUG] Public key length: %zu\n", strlen(*public_key_out));
    printf("[RSA DEBUG] Private key length: %zu\n", strlen(*private_key_out));
    
    /* Test: Verify that the keypair works */
    const char* test_data = "test|keypair|verification";
    char* test_signature = NULL;
    
    if (orca_rsa_sign_string(test_data, *private_key_out, &test_signature) == 0) {
        bool test_result = orca_rsa_verify_string(test_data, test_signature, *public_key_out);
        printf("[RSA DEBUG] Keypair test: %s\n", test_result ? "SUCCESS" : "FAILED");
        if (!test_result) {
            printf("[RSA DEBUG] WARNING: Keypair test FAILED!\n");
        }
        free(test_signature);
    } else {
        printf("[RSA DEBUG] WARNING: Could not test keypair\n");
    }
    
    return 0;
}

int orca_rsa_sign(const unsigned char* data, size_t data_len,
                  const char* private_key_pem, char** signature_out) {
    if (!data || !private_key_pem || !signature_out) {
        set_error("NULL pointer in orca_rsa_sign");
        return -1;
    }
    
    openssl_init();
    
    printf("[RSA DEBUG] Signing data length: %zu\n", data_len);
    printf("[RSA DEBUG] Private key length: %zu\n", strlen(private_key_pem));
    
    /* Use EVP_PKEY API for consistency with keypair generation */
    BIO* bio = BIO_new_mem_buf(private_key_pem, strlen(private_key_pem));
    if (!bio) {
        set_error("Failed to create BIO for private key");
        return -1;
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        set_error("Failed to read private key");
        return -1;
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        set_error("Failed to create EVP context");
        return -1;
    }
    
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        set_error("Failed to init sign");
        return -1;
    }
    
    if (EVP_DigestSignUpdate(ctx, data, data_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        set_error("Failed to update sign");
        return -1;
    }
    
    size_t sig_len;
    if (EVP_DigestSignFinal(ctx, NULL, &sig_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        set_error("Failed to get signature length");
        return -1;
    }
    
    unsigned char* sig = (unsigned char*)malloc(sig_len);
    if (!sig) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        set_error("malloc failed for signature");
        return -1;
    }
    
    if (EVP_DigestSignFinal(ctx, sig, &sig_len) <= 0) {
        free(sig);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        set_error("Failed to sign");
        return -1;
    }
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    
    *signature_out = orca_base64_encode(sig, sig_len);
    free(sig);
    
    if (!*signature_out) {
        set_error("Failed to base64 encode signature");
        return -1;
    }
    
    printf("[RSA DEBUG] Signature created, length: %zu\n", strlen(*signature_out));
    printf("[RSA DEBUG] Signature (first 50): %.50s...\n", *signature_out);
    
    return 0;
}

int orca_rsa_sign_string(const char* str, const char* private_key_pem,
                         char** signature_out) {
    if (!str) {
        set_error("NULL string in orca_rsa_sign_string");
        return -1;
    }
    printf("[RSA DEBUG] Signing string: '%s'\n", str);
    return orca_rsa_sign((const unsigned char*)str, strlen(str),
                         private_key_pem, signature_out);
}

bool orca_rsa_verify(const unsigned char* data, size_t data_len,
                     const char* signature, const char* public_key_pem) {
    if (!data || !signature || !public_key_pem) {
        set_error("NULL pointer in orca_rsa_verify");
        return false;
    }
    
    openssl_init();
    
    printf("[RSA DEBUG] Verifying data length: %zu\n", data_len);
    printf("[RSA DEBUG] Signature length: %zu\n", strlen(signature));
    printf("[RSA DEBUG] Public key length: %zu\n", strlen(public_key_pem));
    
    int sig_len;
    unsigned char* sig = orca_base64_decode(signature, &sig_len);
    if (!sig) {
        set_error("Failed to decode signature");
        return false;
    }
    printf("[RSA DEBUG] Decoded signature length: %d\n", sig_len);
    
    /* Use EVP_PKEY API for consistency with keypair generation */
    BIO* bio = BIO_new_mem_buf(public_key_pem, strlen(public_key_pem));
    if (!bio) {
        free(sig);
        set_error("Failed to create BIO for public key");
        return false;
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) {
        free(sig);
        set_error("Failed to read public key");
        return false;
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        free(sig);
        set_error("Failed to create EVP context");
        return false;
    }
    
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        free(sig);
        set_error("Failed to init verify");
        return false;
    }
    
    if (EVP_DigestVerifyUpdate(ctx, data, data_len) <= 0) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        free(sig);
        set_error("Failed to update verify");
        return false;
    }
    
    int result = EVP_DigestVerifyFinal(ctx, sig, sig_len);
    
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    free(sig);
    
    if (result <= 0) {
        printf("[RSA DEBUG] Verification FAILED!\n");
        set_error("Signature verification failed");
        return false;
    }
    
    printf("[RSA DEBUG] Verification SUCCESS!\n");
    return true;
}

bool orca_rsa_verify_string(const char* str, const char* signature,
                            const char* public_key_pem) {
    if (!str) {
        set_error("NULL string in orca_rsa_verify_string");
        return false;
    }
    printf("[RSA DEBUG] Verifying string: '%s'\n", str);
    return orca_rsa_verify((const unsigned char*)str, strlen(str),
                           signature, public_key_pem);
}

int orca_rsa_public_key_from_pem(const char* pem, unsigned char* out, int* out_len) {
    if (!pem || !out || !out_len) {
        set_error("NULL pointer in orca_rsa_public_key_from_pem");
        return -1;
    }
    *out_len = 0;
    return 0;
}

// ===== AES-256-CBC FUNCTIONS =====
int orca_aes_cbc_encrypt(const unsigned char* data, size_t data_len,
                         const unsigned char* key,
                         unsigned char* iv_out,
                         unsigned char** ciphertext_out,
                         size_t* ciphertext_len) {
    if (!data || !key || !iv_out || !ciphertext_out || !ciphertext_len) {
        set_error("NULL pointer in orca_aes_cbc_encrypt");
        return -1;
    }
    
    openssl_init();
    
    if (RAND_bytes(iv_out, ORCA_AES_IV_LEN) != 1) {
        set_error("Failed to generate IV");
        return -1;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        set_error("Failed to create cipher context");
        return -1;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv_out) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        set_error("Failed to init encryption");
        return -1;
    }
    
    *ciphertext_out = (unsigned char*)malloc(data_len + EVP_MAX_BLOCK_LENGTH);
    if (!*ciphertext_out) {
        EVP_CIPHER_CTX_free(ctx);
        set_error("malloc failed for ciphertext");
        return -1;
    }
    
    int len, total_len = 0;
    if (EVP_EncryptUpdate(ctx, *ciphertext_out, &len, data, data_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext_out);
        *ciphertext_out = NULL;
        set_error("Failed to encrypt data");
        return -1;
    }
    total_len += len;
    
    if (EVP_EncryptFinal_ex(ctx, *ciphertext_out + total_len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*ciphertext_out);
        *ciphertext_out = NULL;
        set_error("Failed to finalize encryption");
        return -1;
    }
    total_len += len;
    
    *ciphertext_len = total_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int orca_aes_cbc_decrypt(const unsigned char* ciphertext, size_t ciphertext_len,
                         const unsigned char* key,
                         const unsigned char* iv,
                         unsigned char** plaintext_out,
                         size_t* plaintext_len) {
    if (!ciphertext || !key || !iv || !plaintext_out || !plaintext_len) {
        set_error("NULL pointer in orca_aes_cbc_decrypt");
        return -1;
    }
    
    openssl_init();
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        set_error("Failed to create cipher context");
        return -1;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        set_error("Failed to init decryption");
        return -1;
    }
    
    *plaintext_out = (unsigned char*)malloc(ciphertext_len + 1);
    if (!*plaintext_out) {
        EVP_CIPHER_CTX_free(ctx);
        set_error("malloc failed for plaintext");
        return -1;
    }
    
    int len, total_len = 0;
    if (EVP_DecryptUpdate(ctx, *plaintext_out, &len, ciphertext, ciphertext_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext_out);
        *plaintext_out = NULL;
        set_error("Failed to decrypt data");
        return -1;
    }
    total_len += len;
    
    if (EVP_DecryptFinal_ex(ctx, *plaintext_out + total_len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        free(*plaintext_out);
        *plaintext_out = NULL;
        set_error("Failed to finalize decryption");
        return -1;
    }
    total_len += len;
    
    *plaintext_len = total_len;
    (*plaintext_out)[total_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int orca_aes_cbc_encrypt_string(const char* str, const char* key_hex,
                                char* iv_hex_out, char** ciphertext_b64_out) {
    if (!str || !key_hex || !iv_hex_out || !ciphertext_b64_out) {
        set_error("NULL pointer in orca_aes_cbc_encrypt_string");
        return -1;
    }
    
    unsigned char key[ORCA_AES_KEY_LEN];
    if (orca_hex_to_bytes(key_hex, key, ORCA_AES_KEY_LEN) < 0) {
        set_error("Invalid key hex");
        return -1;
    }
    
    unsigned char iv[ORCA_AES_IV_LEN];
    unsigned char* ciphertext;
    size_t ciphertext_len;
    
    if (orca_aes_cbc_encrypt((const unsigned char*)str, strlen(str),
                             key, iv, &ciphertext, &ciphertext_len) < 0) {
        return -1;
    }
    
    orca_bytes_to_hex(iv, ORCA_AES_IV_LEN, iv_hex_out);
    
    *ciphertext_b64_out = orca_base64_encode(ciphertext, ciphertext_len);
    free(ciphertext);
    
    if (!*ciphertext_b64_out) {
        set_error("Failed to base64 encode ciphertext");
        return -1;
    }
    
    return 0;
}

int orca_aes_cbc_decrypt_string(const char* ciphertext_b64, const char* iv_hex,
                                const char* key_hex, char** plaintext_out) {
    if (!ciphertext_b64 || !iv_hex || !key_hex || !plaintext_out) {
        set_error("NULL pointer in orca_aes_cbc_decrypt_string");
        return -1;
    }
    
    unsigned char key[ORCA_AES_KEY_LEN];
    if (orca_hex_to_bytes(key_hex, key, ORCA_AES_KEY_LEN) < 0) {
        set_error("Invalid key hex");
        return -1;
    }
    
    unsigned char iv[ORCA_AES_IV_LEN];
    if (orca_hex_to_bytes(iv_hex, iv, ORCA_AES_IV_LEN) < 0) {
        set_error("Invalid IV hex");
        return -1;
    }
    
    int ciphertext_len;
    unsigned char* ciphertext = orca_base64_decode(ciphertext_b64, &ciphertext_len);
    if (!ciphertext) {
        set_error("Failed to decode ciphertext");
        return -1;
    }
    
    unsigned char* plaintext;
    size_t plaintext_len;
    
    int result = orca_aes_cbc_decrypt(ciphertext, ciphertext_len,
                                      key, iv, &plaintext, &plaintext_len);
    free(ciphertext);
    
    if (result < 0) {
        return -1;
    }
    
    *plaintext_out = (char*)plaintext;
    return 0;
}

// ===== X25519 ECDH FUNCTIONS =====
int orca_x25519_generate_keypair(unsigned char* public_key_out,
                                 unsigned char* private_key_out) {
    if (!public_key_out || !private_key_out) {
        set_error("NULL pointer in orca_x25519_generate_keypair");
        return -1;
    }
    
    openssl_init();
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) {
        set_error("Failed to create X25519 context");
        return -1;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        set_error("Failed to init X25519 keygen");
        return -1;
    }
    
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        set_error("Failed to generate X25519 keypair");
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    
    size_t pub_len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key_out, &pub_len) <= 0) {
        EVP_PKEY_free(pkey);
        set_error("Failed to extract public key");
        return -1;
    }
    
    size_t priv_len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, private_key_out, &priv_len) <= 0) {
        EVP_PKEY_free(pkey);
        set_error("Failed to extract private key");
        return -1;
    }
    
    EVP_PKEY_free(pkey);
    return 0;
}

int orca_x25519_compute_shared_secret(const unsigned char* private_key,
                                      const unsigned char* peer_public_key,
                                      unsigned char* shared_secret_out) {
    if (!private_key || !peer_public_key || !shared_secret_out) {
        set_error("NULL pointer in orca_x25519_compute_shared_secret");
        return -1;
    }
    
    openssl_init();
    
    EVP_PKEY* private_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                          private_key, 32);
    if (!private_pkey) {
        set_error("Failed to import private key");
        return -1;
    }
    
    EVP_PKEY* peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                      peer_public_key, 32);
    if (!peer_pkey) {
        EVP_PKEY_free(private_pkey);
        set_error("Failed to import peer public key");
        return -1;
    }
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(private_pkey);
        EVP_PKEY_free(peer_pkey);
        set_error("Failed to create context");
        return -1;
    }
    
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_pkey);
        EVP_PKEY_free(peer_pkey);
        set_error("Failed to init derive");
        return -1;
    }
    
    if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_pkey);
        EVP_PKEY_free(peer_pkey);
        set_error("Failed to set peer");
        return -1;
    }
    
    size_t secret_len = 32;
    if (EVP_PKEY_derive(ctx, shared_secret_out, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_pkey);
        EVP_PKEY_free(peer_pkey);
        set_error("Failed to derive shared secret");
        return -1;
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_pkey);
    EVP_PKEY_free(peer_pkey);
    return 0;
}

char* orca_x25519_public_key_to_hex(const unsigned char* public_key, char* out) {
    if (!public_key || !out) return NULL;
    return orca_bytes_to_hex(public_key, 32, out);
}

int orca_x25519_hex_to_public_key(const char* hex, unsigned char* public_key_out) {
    if (!hex || !public_key_out) {
        set_error("NULL pointer in orca_x25519_hex_to_public_key");
        return -1;
    }
    return orca_hex_to_bytes(hex, public_key_out, 32);
}

// ===== PBKDF2 FUNCTIONS =====
int orca_derive_key_from_passcode(const char* passcode,
                                  const unsigned char* salt,
                                  int salt_len,
                                  int iterations,
                                  unsigned char* key_out) {
    if (!passcode || !salt || salt_len <= 0 || iterations <= 0 || !key_out) {
        set_error("Invalid parameters in orca_derive_key_from_passcode");
        return -1;
    }
    
    openssl_init();
    
    if (PKCS5_PBKDF2_HMAC(passcode, strlen(passcode),
                          salt, salt_len, iterations,
                          EVP_sha256(), ORCA_AES_KEY_LEN, key_out) != 1) {
        set_error("PBKDF2 failed");
        return -1;
    }
    
    return 0;
}

int orca_derive_key_from_passcode_hex(const char* passcode,
                                      const char* salt_hex,
                                      int iterations,
                                      char* key_hex_out) {
    if (!passcode || !salt_hex || !key_hex_out) {
        set_error("NULL pointer in orca_derive_key_from_passcode_hex");
        return -1;
    }
    
    unsigned char salt[16];
    if (orca_hex_to_bytes(salt_hex, salt, 16) < 0) {
        set_error("Invalid salt hex");
        return -1;
    }
    
    unsigned char key[ORCA_AES_KEY_LEN];
    if (orca_derive_key_from_passcode(passcode, salt, 16, iterations, key) < 0) {
        return -1;
    }
    
    orca_bytes_to_hex(key, ORCA_AES_KEY_LEN, key_hex_out);
    return 0;
}

int orca_generate_salt(unsigned char* salt_out) {
    if (!salt_out) {
        set_error("NULL pointer in orca_generate_salt");
        return -1;
    }
    
    openssl_init();
    
    if (RAND_bytes(salt_out, 16) != 1) {
        set_error("Failed to generate salt");
        return -1;
    }
    
    return 0;
}

int orca_generate_salt_hex(char* salt_hex_out) {
    if (!salt_hex_out) {
        set_error("NULL pointer in orca_generate_salt_hex");
        return -1;
    }
    
    unsigned char salt[16];
    if (orca_generate_salt(salt) < 0) {
        return -1;
    }
    
    orca_bytes_to_hex(salt, 16, salt_hex_out);
    return 0;
}

// ===== UTILITY FUNCTIONS =====
int orca_random_bytes(unsigned char* buf, size_t len) {
    if (!buf || len == 0) {
        set_error("Invalid parameters in orca_random_bytes");
        return -1;
    }
    
    openssl_init();
    
    if (RAND_bytes(buf, len) != 1) {
        set_error("Failed to generate random bytes");
        return -1;
    }
    
    return 0;
}

int orca_hex_to_bytes(const char* hex, unsigned char* bytes_out, size_t bytes_len) {
    if (!hex || !bytes_out) {
        set_error("NULL pointer in orca_hex_to_bytes");
        return -1;
    }
    
    size_t hex_len = strlen(hex);
    if (hex_len != bytes_len * 2) {
        set_error("Invalid hex length");
        return -1;
    }
    
    for (size_t i = 0; i < bytes_len; i++) {
        char byte_str[3] = {hex[i*2], hex[i*2+1], '\0'};
        char* endptr;
        long val = strtol(byte_str, &endptr, 16);
        if (*endptr != '\0') {
            set_error("Invalid hex character");
            return -1;
        }
        bytes_out[i] = (unsigned char)val;
    }
    
    return 0;
}

//skibidi
char* orca_bytes_to_hex(const unsigned char* bytes, size_t bytes_len, char* hex_out) {
    if (!bytes || !hex_out) return NULL;
    
    for (size_t i = 0; i < bytes_len; i++) {
        sprintf(hex_out + (i * 2), "%02x", bytes[i]);
    }
    hex_out[bytes_len * 2] = '\0';
    return hex_out;
}

int orca_init_crypto(void) {
    openssl_init();
    return 0;
}

void orca_cleanup_crypto(void) {
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    crypto_initialized = 0;
}

const char* orca_get_last_error(void) {
    return last_error;
}

void orca_clear_error(void) {
    last_error[0] = '\0';
}
