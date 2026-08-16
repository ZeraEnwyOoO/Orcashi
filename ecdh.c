 #include "ecdh.h"
#include "orca_crypto.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static void set_ecdh_error(const char* msg) {
    orca_clear_error();
    fprintf(stderr, "[ECDH ERROR] %s\n", msg);
}

static int openssl_ecdh_init(void) {
    static int initialized = 0;
    if (!initialized) {
        OpenSSL_add_all_algorithms();
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

int orca_ecdh_generate_keypair(OrcaECDHKeypair* keypair_out) {
    if (!keypair_out) {
        set_ecdh_error("NULL pointer in orca_ecdh_generate_keypair");
        return -1;
    }
    
    openssl_ecdh_init();
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) {
        set_ecdh_error("Failed to create X25519 context");
        return -1;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        set_ecdh_error("Failed to init keygen");
        return -1;
    }
    
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        set_ecdh_error("Failed to generate X25519 keypair");
        return -1;
    }
    EVP_PKEY_CTX_free(ctx);
    
    size_t pub_len = ORCA_ECDH_PUBLIC_KEY_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, keypair_out->public_key, &pub_len) <= 0) {
        EVP_PKEY_free(pkey);
        set_ecdh_error("Failed to extract public key");
        return -1;
    }
    
    size_t priv_len = ORCA_ECDH_PRIVATE_KEY_LEN;
    if (EVP_PKEY_get_raw_private_key(pkey, keypair_out->private_key, &priv_len) <= 0) {
        EVP_PKEY_free(pkey);
        set_ecdh_error("Failed to extract private key");
        return -1;
    }
    
    EVP_PKEY_free(pkey);
    return 0;
}

int orca_ecdh_generate_ephemeral(OrcaECDHKeypair* keypair_out) {
    return orca_ecdh_generate_keypair(keypair_out);
}

char* orca_ecdh_public_key_to_hex(const unsigned char* public_key, char* hex_out) {
    if (!public_key || !hex_out) return NULL;
    return orca_bytes_to_hex(public_key, ORCA_ECDH_PUBLIC_KEY_LEN, hex_out);
}

int orca_ecdh_hex_to_public_key(const char* hex, unsigned char* public_key_out) {
    if (!hex || !public_key_out) {
        set_ecdh_error("NULL pointer in orca_ecdh_hex_to_public_key");
        return -1;
    }
    return orca_hex_to_bytes(hex, public_key_out, ORCA_ECDH_PUBLIC_KEY_LEN);
}

char* orca_ecdh_private_key_to_hex(const unsigned char* private_key, char* hex_out) {
    if (!private_key || !hex_out) return NULL;
    return orca_bytes_to_hex(private_key, ORCA_ECDH_PRIVATE_KEY_LEN, hex_out);
}

int orca_ecdh_hex_to_private_key(const char* hex, unsigned char* private_key_out) {
    if (!hex || !private_key_out) {
        set_ecdh_error("NULL pointer in orca_ecdh_hex_to_private_key");
        return -1;
    }
    return orca_hex_to_bytes(hex, private_key_out, ORCA_ECDH_PRIVATE_KEY_LEN);
}

int orca_ecdh_compute_shared_secret(const unsigned char* private_key,
                                    const unsigned char* peer_public_key,
                                    unsigned char* shared_secret_out) {
    if (!private_key || !peer_public_key || !shared_secret_out) {
        set_ecdh_error("NULL pointer in orca_ecdh_compute_shared_secret");
        return -1;
    }
    
    openssl_ecdh_init();
    
    EVP_PKEY* private_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                          private_key,
                                                          ORCA_ECDH_PRIVATE_KEY_LEN);
    if (!private_pkey) {
        set_ecdh_error("Failed to import private key");
        return -1;
    }
    
    EVP_PKEY* peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                      peer_public_key,
                                                      ORCA_ECDH_PUBLIC_KEY_LEN);
    if (!peer_pkey) {
        EVP_PKEY_free(private_pkey);
        set_ecdh_error("Failed to import peer public key");
        return -1;
    }
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_pkey, NULL);
    if (!ctx) {
        EVP_PKEY_free(private_pkey);
        EVP_PKEY_free(peer_pkey);
        set_ecdh_error("Failed to create context");
        return -1;
    }
    
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_pkey);
        EVP_PKEY_free(peer_pkey);
        set_ecdh_error("Failed to init derive");
        return -1;
    }
    
    if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_pkey);
        EVP_PKEY_free(peer_pkey);
        set_ecdh_error("Failed to set peer");
        return -1;
    }
    
    size_t secret_len = ORCA_ECDH_SHARED_SECRET_LEN;
    if (EVP_PKEY_derive(ctx, shared_secret_out, &secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(private_pkey);
        EVP_PKEY_free(peer_pkey);
        set_ecdh_error("Failed to derive shared secret");
        return -1;
    }
    
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_pkey);
    EVP_PKEY_free(peer_pkey);
    
    if (secret_len != ORCA_ECDH_SHARED_SECRET_LEN) {
        set_ecdh_error("Unexpected shared secret length");
        return -1;
    }
    
    return 0;
}

int orca_ecdh_compute_shared_secret_keypair(const OrcaECDHKeypair* keypair,
                                            const unsigned char* peer_public_key,
                                            unsigned char* shared_secret_out) {
    if (!keypair || !peer_public_key || !shared_secret_out) {
        set_ecdh_error("NULL pointer in orca_ecdh_compute_shared_secret_keypair");
        return -1;
    }
    return orca_ecdh_compute_shared_secret(keypair->private_key,
                                           peer_public_key,
                                           shared_secret_out);
}

int orca_ecdh_compute_shared_secret_hex(const char* private_key_hex,
                                        const char* peer_public_key_hex,
                                        char* shared_secret_hex_out) {
    if (!private_key_hex || !peer_public_key_hex || !shared_secret_hex_out) {
        set_ecdh_error("NULL pointer in orca_ecdh_compute_shared_secret_hex");
        return -1;
    }
    
    unsigned char private_key[ORCA_ECDH_PRIVATE_KEY_LEN];
    unsigned char peer_public_key[ORCA_ECDH_PUBLIC_KEY_LEN];
    unsigned char shared_secret[ORCA_ECDH_SHARED_SECRET_LEN];
    
    if (orca_ecdh_hex_to_private_key(private_key_hex, private_key) < 0) {
        set_ecdh_error("Invalid private key hex");
        return -1;
    }
    
    if (orca_ecdh_hex_to_public_key(peer_public_key_hex, peer_public_key) < 0) {
        set_ecdh_error("Invalid peer public key hex");
        return -1;
    }
    
    if (orca_ecdh_compute_shared_secret(private_key, peer_public_key, shared_secret) < 0) {
        return -1;
    }
    
    orca_bytes_to_hex(shared_secret, ORCA_ECDH_SHARED_SECRET_LEN, shared_secret_hex_out);
    
    zeroize(private_key, ORCA_ECDH_PRIVATE_KEY_LEN);
    zeroize(shared_secret, ORCA_ECDH_SHARED_SECRET_LEN);
    
    return 0;
}

int orca_ecdh_derive_aes_key(const unsigned char* shared_secret,
                             const unsigned char* salt, size_t salt_len,
                             const unsigned char* info, size_t info_len,
                             unsigned char* aes_key_out) {
    if (!shared_secret || !aes_key_out) {
        set_ecdh_error("NULL pointer in orca_ecdh_derive_aes_key");
        return -1;
    }
    
    openssl_ecdh_init();
    
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) {
        set_ecdh_error("Failed to create HKDF context");
        return -1;
    }
    
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        set_ecdh_error("Failed to init HKDF");
        return -1;
    }
    
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        set_ecdh_error("Failed to set HKDF digest");
        return -1;
    }
    
    if (salt && salt_len > 0) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            set_ecdh_error("Failed to set HKDF salt");
            return -1;
        }
    }
    
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, shared_secret, ORCA_ECDH_SHARED_SECRET_LEN) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        set_ecdh_error("Failed to set HKDF key");
        return -1;
    }
    
    if (info && info_len > 0) {
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, info_len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            set_ecdh_error("Failed to set HKDF info");
            return -1;
        }
    }
    
    size_t key_len = 32;
    if (EVP_PKEY_derive(ctx, aes_key_out, &key_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        set_ecdh_error("Failed to derive AES key");
        return -1;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    if (key_len != 32) {
        set_ecdh_error("Unexpected AES key length");
        return -1;
    }
    
    return 0;
}

int orca_ecdh_derive_aes_key_hex(const char* shared_secret_hex,
                                 const char* salt_hex,
                                 const unsigned char* info, size_t info_len,
                                 char* aes_key_hex_out) {
    if (!shared_secret_hex || !aes_key_hex_out) {
        set_ecdh_error("NULL pointer in orca_ecdh_derive_aes_key_hex");
        return -1;
    }
    
    unsigned char shared_secret[ORCA_ECDH_SHARED_SECRET_LEN];
    if (orca_hex_to_bytes(shared_secret_hex, shared_secret,
                          ORCA_ECDH_SHARED_SECRET_LEN) < 0) {
        set_ecdh_error("Invalid shared secret hex");
        return -1;
    }
    
    unsigned char salt[16];
    size_t salt_len = 0;
    if (salt_hex) {
        salt_len = 16;
        if (orca_hex_to_bytes(salt_hex, salt, salt_len) < 0) {
            set_ecdh_error("Invalid salt hex");
            return -1;
        }
    }
    
    unsigned char aes_key[32];
    if (orca_ecdh_derive_aes_key(shared_secret, salt_hex ? salt : NULL,
                                 salt_len, info, info_len, aes_key) < 0) {
        zeroize(shared_secret, ORCA_ECDH_SHARED_SECRET_LEN);
        zeroize(aes_key, 32);
        return -1;
    }
    
    orca_bytes_to_hex(aes_key, 32, aes_key_hex_out);
    
    zeroize(shared_secret, ORCA_ECDH_SHARED_SECRET_LEN);
    zeroize(aes_key, 32);
    
    return 0;
}

int orca_ecdh_session_init(OrcaECDSession* session,
                           bool is_initiator,
                           const unsigned char* peer_public_key) {
    if (!session) {
        set_ecdh_error("NULL pointer in orca_ecdh_session_init");
        return -1;
    }
    
    memset(session, 0, sizeof(OrcaECDSession));
    session->is_initiator = is_initiator;
    session->created_at = time(NULL);
    session->expires_at = session->created_at + 3600;
    
    if (orca_ecdh_generate_ephemeral(&session->ephemeral_keypair) < 0) {
        set_ecdh_error("Failed to generate ephemeral keypair");
        return -1;
    }
    
    if (peer_public_key) {
        memcpy(session->peer_public_key, peer_public_key,
               ORCA_ECDH_PUBLIC_KEY_LEN);
    }
    
    unsigned char hash[32];
    orca_hash(session->ephemeral_keypair.public_key,
              ORCA_ECDH_PUBLIC_KEY_LEN, hash);
    memcpy(session->session_id, hash, 32);
    
    return 0;
}

int orca_ecdh_session_initiate(OrcaECDSession* session,
                               unsigned char* public_key_out) {
    if (!session || !public_key_out) {
        set_ecdh_error("NULL pointer in orca_ecdh_session_initiate");
        return -1;
    }
    
    if (!session->is_initiator) {
        set_ecdh_error("Session is not an initiator");
        return -1;
    }
    
    memcpy(public_key_out, session->ephemeral_keypair.public_key,
           ORCA_ECDH_PUBLIC_KEY_LEN);
    
    return 0;
}

int orca_ecdh_session_respond(OrcaECDSession* session,
                              const unsigned char* peer_public_key,
                              unsigned char* public_key_out) {
    if (!session || !peer_public_key || !public_key_out) {
        set_ecdh_error("NULL pointer in orca_ecdh_session_respond");
        return -1;
    }
    
    if (session->is_initiator) {
        set_ecdh_error("Session is an initiator, not responder");
        return -1;
    }
    
    memcpy(session->peer_public_key, peer_public_key,
           ORCA_ECDH_PUBLIC_KEY_LEN);
    
    if (orca_ecdh_compute_shared_secret_keypair(&session->ephemeral_keypair,
                                                peer_public_key,
                                                session->shared_secret) < 0) {
        set_ecdh_error("Failed to compute shared secret");
        return -1;
    }
    
    session->established = true;
    
    memcpy(public_key_out, session->ephemeral_keypair.public_key,
           ORCA_ECDH_PUBLIC_KEY_LEN);
    
    return 0;
}

int orca_ecdh_session_complete(OrcaECDSession* session,
                               const unsigned char* peer_public_key) {
    if (!session || !peer_public_key) {
        set_ecdh_error("NULL pointer in orca_ecdh_session_complete");
        return -1;
    }
    
    if (!session->is_initiator) {
        set_ecdh_error("Session is not an initiator");
        return -1;
    }
    
    memcpy(session->peer_public_key, peer_public_key,
           ORCA_ECDH_PUBLIC_KEY_LEN);
    
    if (orca_ecdh_compute_shared_secret_keypair(&session->ephemeral_keypair,
                                                peer_public_key,
                                                session->shared_secret) < 0) {
        set_ecdh_error("Failed to compute shared secret");
        return -1;
    }
    
    session->established = true;
    return 0;
}

int orca_ecdh_session_get_shared_secret(OrcaECDSession* session,
                                        unsigned char* secret_out) {
    if (!session || !secret_out) {
        set_ecdh_error("NULL pointer in orca_ecdh_session_get_shared_secret");
        return -1;
    }
    
    if (!session->established) {
        set_ecdh_error("Session not established yet");
        return -1;
    }
    
    memcpy(secret_out, session->shared_secret, ORCA_ECDH_SHARED_SECRET_LEN);
    return 0;
}

void orca_ecdh_session_destroy(OrcaECDSession* session) {
    if (!session) return;
    
    zeroize(session->shared_secret, ORCA_ECDH_SHARED_SECRET_LEN);
    zeroize(session->ephemeral_keypair.private_key, ORCA_ECDH_PRIVATE_KEY_LEN);
    zeroize(session->peer_public_key, ORCA_ECDH_PUBLIC_KEY_LEN);
    zeroize(session->session_id, 32);
    memset(session, 0, sizeof(OrcaECDSession));
}

bool orca_ecdh_session_is_established(OrcaECDSession* session) {
    return session && session->established;
}

bool orca_ecdh_session_expired(OrcaECDSession* session) {
    if (!session) return true;
    return time(NULL) > session->expires_at;
}

int orca_ecdh_keypair_to_hex(const OrcaECDHKeypair* keypair,
                             char* public_hex_out,
                             char* private_hex_out) {
    if (!keypair || !public_hex_out || !private_hex_out) {
        set_ecdh_error("NULL pointer in orca_ecdh_keypair_to_hex");
        return -1;
    }
    
    orca_ecdh_public_key_to_hex(keypair->public_key, public_hex_out);
    orca_ecdh_private_key_to_hex(keypair->private_key, private_hex_out);
    return 0;
}

int orca_ecdh_keypair_from_hex(const char* public_hex,
                               const char* private_hex,
                               OrcaECDHKeypair* keypair_out) {
    if (!public_hex || !private_hex || !keypair_out) {
        set_ecdh_error("NULL pointer in orca_ecdh_keypair_from_hex");
        return -1;
    }
    
    if (orca_ecdh_hex_to_public_key(public_hex, keypair_out->public_key) < 0) {
        set_ecdh_error("Invalid public key hex");
        return -1;
    }
    
    if (orca_ecdh_hex_to_private_key(private_hex, keypair_out->private_key) < 0) {
        set_ecdh_error("Invalid private key hex");
        return -1;
    }
    
    return 0;
}

int orca_ecdh_test_self(void) {
    printf("[ECDH TEST] Running self-test...\n");
    
    OrcaECDHKeypair alice, bob;
    if (orca_ecdh_generate_keypair(&alice) < 0) {
        printf("[ECDH TEST] FAIL: Alice keypair generation\n");
        return -1;
    }
    if (orca_ecdh_generate_keypair(&bob) < 0) {
        printf("[ECDH TEST] FAIL: Bob keypair generation\n");
        return -1;
    }
    
    unsigned char secret_alice[ORCA_ECDH_SHARED_SECRET_LEN];
    unsigned char secret_bob[ORCA_ECDH_SHARED_SECRET_LEN];
    
    if (orca_ecdh_compute_shared_secret(alice.private_key, bob.public_key,
                                        secret_alice) < 0) {
        printf("[ECDH TEST] FAIL: Alice shared secret\n");
        return -1;
    }
    
    if (orca_ecdh_compute_shared_secret(bob.private_key, alice.public_key,
                                        secret_bob) < 0) {
        printf("[ECDH TEST] FAIL: Bob shared secret\n");
        return -1;
    }
    
    if (memcmp(secret_alice, secret_bob, ORCA_ECDH_SHARED_SECRET_LEN) != 0) {
        printf("[ECDH TEST] FAIL: Shared secrets don't match!\n");
        return -1;
    }
    
    printf("[ECDH TEST] SUCCESS: Shared secrets match!\n");
    return 0;
}
