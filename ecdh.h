#ifndef ORCA_ECDH_H
#define ORCA_ECDH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

#define ORCA_ECDH_PUBLIC_KEY_LEN 32
#define ORCA_ECDH_PRIVATE_KEY_LEN 32
#define ORCA_ECDH_SHARED_SECRET_LEN 32
#define ORCA_ECDH_KEY_AGREEMENT_LEN 32

/* ============================================================================
 * DATA TYPES
 * ============================================================================ */

typedef struct {
    unsigned char public_key[ORCA_ECDH_PUBLIC_KEY_LEN];
    unsigned char private_key[ORCA_ECDH_PRIVATE_KEY_LEN];
} OrcaECDHKeypair;

typedef struct {
    unsigned char shared_secret[ORCA_ECDH_SHARED_SECRET_LEN];
} OrcaECDHSharedSecret;

/* ============================================================================
 * KEYPAIR MANAGEMENT
 * ============================================================================ */

/**
 * orca_ecdh_generate_keypair - Generate X25519 keypair
 * @param keypair_out: Output keypair
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_generate_keypair(OrcaECDHKeypair* keypair_out);

/**
 * orca_ecdh_generate_ephemeral - Generate ephemeral keypair (one-time use)
 * @param keypair_out: Output keypair
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_generate_ephemeral(OrcaECDHKeypair* keypair_out);

/**
 * orca_ecdh_public_key_to_hex - Convert public key to hex string
 * @param public_key: 32-byte public key
 * @param hex_out: Output buffer (must be 65 bytes)
 * @return: Pointer to hex_out
 */
char* orca_ecdh_public_key_to_hex(const unsigned char* public_key, char* hex_out);

/**
 * orca_ecdh_hex_to_public_key - Convert hex string to public key
 * @param hex: 64-character hex string
 * @param public_key_out: Output public key (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_hex_to_public_key(const char* hex, unsigned char* public_key_out);

/**
 * orca_ecdh_private_key_to_hex - Convert private key to hex string
 * @param private_key: 32-byte private key
 * @param hex_out: Output buffer (must be 65 bytes)
 * @return: Pointer to hex_out
 */
char* orca_ecdh_private_key_to_hex(const unsigned char* private_key, char* hex_out);

/**
 * orca_ecdh_hex_to_private_key - Convert hex string to private key
 * @param hex: 64-character hex string
 * @param private_key_out: Output private key (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_hex_to_private_key(const char* hex, unsigned char* private_key_out);

/* ============================================================================
 * KEY EXCHANGE
 * ============================================================================ */

/**
 * orca_ecdh_compute_shared_secret - Compute shared secret from private and peer public keys
 * @param private_key: Your private key (32 bytes)
 * @param peer_public_key: Peer's public key (32 bytes)
 * @param shared_secret_out: Output shared secret (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_compute_shared_secret(const unsigned char* private_key,
                                    const unsigned char* peer_public_key,
                                    unsigned char* shared_secret_out);

/**
 * orca_ecdh_compute_shared_secret_keypair - Compute shared secret from keypair and peer public key
 * @param keypair: Your keypair
 * @param peer_public_key: Peer's public key (32 bytes)
 * @param shared_secret_out: Output shared secret (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_compute_shared_secret_keypair(const OrcaECDHKeypair* keypair,
                                            const unsigned char* peer_public_key,
                                            unsigned char* shared_secret_out);

/**
 * orca_ecdh_compute_shared_secret_hex - Compute shared secret and return as hex
 * @param private_key_hex: Your private key (64 hex chars)
 * @param peer_public_key_hex: Peer's public key (64 hex chars)
 * @param shared_secret_hex_out: Output hex shared secret (must be 65 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_compute_shared_secret_hex(const char* private_key_hex,
                                        const char* peer_public_key_hex,
                                        char* shared_secret_hex_out);

/* ============================================================================
 * KEY DERIVATION (HKDF)
 * ============================================================================ */

/**
 * orca_ecdh_derive_aes_key - Derive AES-256 key from shared secret
 * @param shared_secret: Shared secret (32 bytes)
 * @param salt: Optional salt (can be NULL)
 * @param salt_len: Length of salt
 * @param info: Optional context info (can be NULL)
 * @param info_len: Length of info
 * @param aes_key_out: Output AES key (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_derive_aes_key(const unsigned char* shared_secret,
                             const unsigned char* salt, size_t salt_len,
                             const unsigned char* info, size_t info_len,
                             unsigned char* aes_key_out);

/**
 * orca_ecdh_derive_aes_key_hex - Derive AES-256 key as hex string
 * @param shared_secret_hex: Shared secret (64 hex chars)
 * @param salt_hex: Optional salt (can be NULL)
 * @param info: Optional context info (can be NULL)
 * @param info_len: Length of info
 * @param aes_key_hex_out: Output AES key hex (must be 65 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_derive_aes_key_hex(const char* shared_secret_hex,
                                 const char* salt_hex,
                                 const unsigned char* info, size_t info_len,
                                 char* aes_key_hex_out);

/**
 * orca_ecdh_derive_keys - Derive multiple keys from shared secret
 * @param shared_secret: Shared secret (32 bytes)
 * @param salt: Optional salt (can be NULL)
 * @param salt_len: Length of salt
 * @param key_count: Number of keys to derive
 * @param keys_out: Output array of keys (each 32 bytes)
 * @param key_len: Length of each key (must be 32)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_derive_keys(const unsigned char* shared_secret,
                          const unsigned char* salt, size_t salt_len,
                          int key_count,
                          unsigned char* keys_out, size_t key_len);

/* ============================================================================
 * SESSION MANAGEMENT
 * ============================================================================ */

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

/**
 * orca_ecdh_session_init - Initialize a new ECDH session
 * @param session: Session to initialize
 * @param is_initiator: true if this is the initiator
 * @param peer_public_key: Peer's public key (can be NULL if initiator)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_session_init(OrcaECDSession* session,
                           bool is_initiator,
                           const unsigned char* peer_public_key);

/**
 * orca_ecdh_session_initiate - Initiate a session (generate ephemeral key)
 * @param session: Session
 * @param public_key_out: Output public key to send to peer (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_session_initiate(OrcaECDSession* session,
                               unsigned char* public_key_out);

/**
 * orca_ecdh_session_respond - Respond to a session (complete key exchange)
 * @param session: Session
 * @param peer_public_key: Peer's public key (32 bytes)
 * @param public_key_out: Output public key to send to peer (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_session_respond(OrcaECDSession* session,
                              const unsigned char* peer_public_key,
                              unsigned char* public_key_out);

/**
 * orca_ecdh_session_complete - Complete key exchange (compute shared secret)
 * @param session: Session
 * @param peer_public_key: Peer's public key (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_session_complete(OrcaECDSession* session,
                               const unsigned char* peer_public_key);

/**
 * orca_ecdh_session_get_shared_secret - Get shared secret from session
 * @param session: Session
 * @param secret_out: Output shared secret (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_session_get_shared_secret(OrcaECDSession* session,
                                        unsigned char* secret_out);

/**
 * orca_ecdh_session_destroy - Destroy session and zero sensitive data
 * @param session: Session to destroy
 */
void orca_ecdh_session_destroy(OrcaECDSession* session);

/**
 * orca_ecdh_session_is_established - Check if session is established
 * @param session: Session
 * @return: true if established, false otherwise
 */
bool orca_ecdh_session_is_established(OrcaECDSession* session);

/**
 * orca_ecdh_session_expired - Check if session is expired
 * @param session: Session
 * @return: true if expired, false otherwise
 */
bool orca_ecdh_session_expired(OrcaECDSession* session);

/* ============================================================================
 * KEY SERIALIZATION
 * ============================================================================ */

/**
 * orca_ecdh_keypair_to_hex - Convert keypair to hex strings
 * @param keypair: Keypair
 * @param public_hex_out: Output public key hex (must be 65 bytes)
 * @param private_hex_out: Output private key hex (must be 65 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_keypair_to_hex(const OrcaECDHKeypair* keypair,
                             char* public_hex_out,
                             char* private_hex_out);

/**
 * orca_ecdh_keypair_from_hex - Convert hex strings to keypair
 * @param public_hex: Public key hex (64 chars)
 * @param private_hex: Private key hex (64 chars)
 * @param keypair_out: Output keypair
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_keypair_from_hex(const char* public_hex,
                               const char* private_hex,
                               OrcaECDHKeypair* keypair_out);

/* ============================================================================
 * PERFECT FORWARD SECRECY
 * ============================================================================ */

/**
 * orca_ecdh_generate_pfs_keypair - Generate keypair with PFS (Perfect Forward Secrecy)
 * @param keypair_out: Output keypair
 * @param seed: Optional seed (can be NULL)
 * @param seed_len: Length of seed
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_generate_pfs_keypair(OrcaECDHKeypair* keypair_out,
                                   const unsigned char* seed,
                                   size_t seed_len);

/**
 * orca_ecdh_compute_pfs_secret - Compute PFS shared secret
 * @param private_key: Private key (32 bytes)
 * @param peer_public_key: Peer's public key (32 bytes)
 * @param previous_secret: Previous shared secret (32 bytes, can be NULL)
 * @param secret_out: Output shared secret (32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_compute_pfs_secret(const unsigned char* private_key,
                                 const unsigned char* peer_public_key,
                                 const unsigned char* previous_secret,
                                 unsigned char* secret_out);

/* ============================================================================
 * DEBUG FUNCTIONS
 * ============================================================================ */

/**
 * orca_ecdh_debug_print_keypair - Print keypair for debugging
 * @param keypair: Keypair
 * @param label: Label to print (can be NULL)
 */
void orca_ecdh_debug_print_keypair(const OrcaECDHKeypair* keypair,
                                   const char* label);

/**
 * orca_ecdh_debug_print_public_key - Print public key for debugging
 * @param public_key: Public key (32 bytes)
 * @param label: Label to print (can be NULL)
 */
void orca_ecdh_debug_print_public_key(const unsigned char* public_key,
                                      const char* label);

/**
 * orca_ecdh_debug_print_shared_secret - Print shared secret for debugging
 * @param shared_secret: Shared secret (32 bytes)
 * @param label: Label to print (can be NULL)
 */
void orca_ecdh_debug_print_shared_secret(const unsigned char* shared_secret,
                                         const char* label);

/* ============================================================================
 * TEST FUNCTIONS
 * ============================================================================ */

/**
 * orca_ecdh_test_self - Self-test ECDH implementation
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_test_self(void);

/**
 * orca_ecdh_test_vector - Test with known vectors
 * @return: 0 on success, -1 on failure
 */
int orca_ecdh_test_vector(void);

#ifdef __cplusplus
}
#endif

#endif /* ORCA_ECDH_H */
