 #ifndef ORCA_ECDH_H
#define ORCA_ECDH_H

#include <time.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ORCA_ECDH_PUBLIC_KEY_LEN 32
#define ORCA_ECDH_PRIVATE_KEY_LEN 32
#define ORCA_ECDH_SHARED_SECRET_LEN 32
#define ORCA_ECDH_KEY_AGREEMENT_LEN 32

typedef struct {
    unsigned char public_key[ORCA_ECDH_PUBLIC_KEY_LEN];
    unsigned char private_key[ORCA_ECDH_PRIVATE_KEY_LEN];
} OrcaECDHKeypair;

typedef struct {
    unsigned char shared_secret[ORCA_ECDH_SHARED_SECRET_LEN];
} OrcaECDHSharedSecret;

int orca_ecdh_generate_keypair(OrcaECDHKeypair* keypair_out);
int orca_ecdh_generate_ephemeral(OrcaECDHKeypair* keypair_out);
char* orca_ecdh_public_key_to_hex(const unsigned char* public_key, char* hex_out);
int orca_ecdh_hex_to_public_key(const char* hex, unsigned char* public_key_out);
char* orca_ecdh_private_key_to_hex(const unsigned char* private_key, char* hex_out);
int orca_ecdh_hex_to_private_key(const char* hex, unsigned char* private_key_out);

int orca_ecdh_compute_shared_secret(const unsigned char* private_key,
                                    const unsigned char* peer_public_key,
                                    unsigned char* shared_secret_out);
int orca_ecdh_compute_shared_secret_keypair(const OrcaECDHKeypair* keypair,
                                            const unsigned char* peer_public_key,
                                            unsigned char* shared_secret_out);
int orca_ecdh_compute_shared_secret_hex(const char* private_key_hex,
                                        const char* peer_public_key_hex,
                                        char* shared_secret_hex_out);

int orca_ecdh_derive_aes_key(const unsigned char* shared_secret,
                             const unsigned char* salt, size_t salt_len,
                             const unsigned char* info, size_t info_len,
                             unsigned char* aes_key_out);
int orca_ecdh_derive_aes_key_hex(const char* shared_secret_hex,
                                 const char* salt_hex,
                                 const unsigned char* info, size_t info_len,
                                 char* aes_key_hex_out);
int orca_ecdh_derive_keys(const unsigned char* shared_secret,
                          const unsigned char* salt, size_t salt_len,
                          int key_count,
                          unsigned char* keys_out, size_t key_len);

typedef struct {
    unsigned char session_id[32];
    unsigned char shared_secret[ORCA_ECDH_SHARED_SECRET_LEN];
    OrcaECDHKeypair ephemeral_keypair;
    unsigned char peer_public_key[ORCA_ECDH_PUBLIC_KEY_LEN];
    time_t created_at;
    time_t expires_at;
    bool is_initiator;
    bool established;
} OrcaECDSession;

int orca_ecdh_session_init(OrcaECDSession* session,
                           bool is_initiator,
                           const unsigned char* peer_public_key);
int orca_ecdh_session_initiate(OrcaECDSession* session,
                               unsigned char* public_key_out);
int orca_ecdh_session_respond(OrcaECDSession* session,
                              const unsigned char* peer_public_key,
                              unsigned char* public_key_out);
int orca_ecdh_session_complete(OrcaECDSession* session,
                               const unsigned char* peer_public_key);
int orca_ecdh_session_get_shared_secret(OrcaECDSession* session,
                                        unsigned char* secret_out);
void orca_ecdh_session_destroy(OrcaECDSession* session);
bool orca_ecdh_session_is_established(OrcaECDSession* session);
bool orca_ecdh_session_expired(OrcaECDSession* session);

int orca_ecdh_keypair_to_hex(const OrcaECDHKeypair* keypair,
                             char* public_hex_out,
                             char* private_hex_out);
int orca_ecdh_keypair_from_hex(const char* public_hex,
                               const char* private_hex,
                               OrcaECDHKeypair* keypair_out);

int orca_ecdh_generate_pfs_keypair(OrcaECDHKeypair* keypair_out,
                                   const unsigned char* seed,
                                   size_t seed_len);
int orca_ecdh_compute_pfs_secret(const unsigned char* private_key,
                                 const unsigned char* peer_public_key,
                                 const unsigned char* previous_secret,
                                 unsigned char* secret_out);

void orca_ecdh_debug_print_keypair(const OrcaECDHKeypair* keypair,
                                   const char* label);
void orca_ecdh_debug_print_public_key(const unsigned char* public_key,
                                      const char* label);
void orca_ecdh_debug_print_shared_secret(const unsigned char* shared_secret,
                                         const char* label);

int orca_ecdh_test_self(void);
int orca_ecdh_test_vector(void);

#ifdef __cplusplus
}
#endif

#endif
