#ifndef ORCA_IDENTITY_H
#define ORCA_IDENTITY_H

#include "orca_crypto.h"
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

#define ORCA_IDENTITY_HOME "/tmp/.orcashi/identity/"
#define ORCA_IDENTITY_FILE ORCA_IDENTITY_HOME "identity.json"
#define ORCA_PUBLIC_KEY_FILE ORCA_IDENTITY_HOME "public.pem"
#define ORCA_PRIVATE_KEY_FILE ORCA_IDENTITY_HOME "private.enc"
#define ORCA_SIGNATURE_FILE ORCA_IDENTITY_HOME "signature.txt"
#define ORCA_SALT_FILE ORCA_IDENTITY_HOME "salt.hex"
#define ORCA_METADATA_FILE ORCA_IDENTITY_HOME "metadata.json"

#define ORCA_IDENTITY_VERSION "1.0"
#define ORCA_PBKDF2_ITERATIONS 100000
#define ORCA_SALT_LEN 16

/* ============================================================================
 * DATA TYPES
 * ============================================================================ */

typedef enum {
    ORCA_IDENTITY_MODE_NORMAL = 0,   /* 3-digit ID (legacy) */
    ORCA_IDENTITY_MODE_SECURE = 1    /* RSA + passcode */
} OrcaIdentityMode;

typedef struct {
    char id[ORCA_ID_LEN];                    /* Human-readable ID */
    char name[ORCA_NAME_LEN];                /* User name (optional) */
    char role[ORCA_ROLE_LEN];                /* Role (e.g., "user", "admin") */
    OrcaIdentityMode mode;                   /* Normal or Secure */
    time_t created_at;                       /* Creation timestamp */
    time_t last_used;                        /* Last use timestamp */
    bool verified;                           /* Whether identity is verified */
    char public_key[ORCA_PUBKEY_LEN];        /* RSA public key (PEM) */
    char private_key_encrypted[ORCA_ENCRYPTED_LEN]; /* AES-encrypted private key */
    char signature[ORCA_SIG_LEN];            /* Self-signature */
    char salt_hex[ORCA_SALT_LEN * 2 + 1];    /* Salt for PBKDF2 */
    char version[16];                        /* Identity version */
} OrcaIdentity;

typedef struct {
    OrcaIdentity identities[10];             /* Multiple identities support */
    int count;                               /* Number of identities */
    char default_id[ORCA_ID_LEN];            /* Default identity ID */
} OrcaIdentityStore;

/* ============================================================================
 * IDENTITY LIFECYCLE FUNCTIONS
 * ============================================================================ */

/**
 * orca_identity_create - Create a new secure identity
 * @param name: User name (optional, can be NULL)
 * @param passcode: User passcode (min 8 chars)
 * @param role: Role (e.g., "user", "admin")
 * @param identity_out: Output identity (must be freed by caller)
 * @return: 0 on success, -1 on failure
 */
int orca_identity_create(const char* name, const char* passcode,
                         const char* role, OrcaIdentity* identity_out);

/**
 * orca_identity_create_normal - Create a normal 3-digit identity (legacy)
 * @param id: 3-digit ID string (e.g., "087")
 * @param ip: IP address
 * @param identity_out: Output identity
 * @return: 0 on success, -1 on failure
 */
int orca_identity_create_normal(const char* id, const char* ip,
                                OrcaIdentity* identity_out);

/**
 * orca_identity_load - Load identity from storage
 * @param identity_out: Output identity
 * @param passcode: Passcode to decrypt private key (can be NULL for normal mode)
 * @return: 0 on success, -1 on failure
 */
int orca_identity_load(OrcaIdentity* identity_out, const char* passcode);

/**
 * orca_identity_load_by_id - Load identity by ID
 * @param id: Identity ID to load
 * @param identity_out: Output identity
 * @param passcode: Passcode to decrypt private key
 * @return: 0 on success, -1 on failure
 */
int orca_identity_load_by_id(const char* id, OrcaIdentity* identity_out,
                             const char* passcode);

/**
 * orca_identity_save - Save identity to storage
 * @param identity: Identity to save
 * @return: 0 on success, -1 on failure
 */
int orca_identity_save(OrcaIdentity* identity);

/**
 * orca_identity_delete - Delete identity from storage
 * @param id: Identity ID to delete (NULL for current/default)
 * @return: 0 on success, -1 on failure
 */
int orca_identity_delete(const char* id);

/**
 * orca_identity_exists - Check if identity exists
 * @param id: Identity ID to check (NULL for any)
 * @return: true if exists, false otherwise
 */
bool orca_identity_exists(const char* id);

/**
 * orca_identity_get_default - Get default identity ID
 * @param id_out: Output buffer for ID (must be at least ORCA_ID_LEN)
 * @return: 0 on success, -1 on failure
 */
int orca_identity_get_default(char* id_out);

/**
 * orca_identity_set_default - Set default identity
 * @param id: Identity ID to set as default
 * @return: 0 on success, -1 on failure
 */
int orca_identity_set_default(const char* id);

/* ============================================================================
 * IDENTITY VERIFICATION FUNCTIONS
 * ============================================================================ */

/**
 * orca_identity_verify - Verify identity signature
 * @param identity: Identity to verify
 * @return: true if verified, false otherwise
 */
bool orca_identity_verify(OrcaIdentity* identity);

/**
 * orca_identity_verify_with_passcode - Verify identity with passcode
 * @param identity: Identity to verify
 * @param passcode: Passcode to decrypt private key
 * @return: true if verified, false otherwise
 */
bool orca_identity_verify_with_passcode(OrcaIdentity* identity,
                                        const char* passcode);

/**
 * orca_identity_sign_message - Sign a message with identity
 * @param identity: Identity to sign with
 * @param message: Message to sign
 * @param signature_out: Output signature (base64, must be freed)
 * @return: 0 on success, -1 on failure
 */
int orca_identity_sign_message(OrcaIdentity* identity, const char* message,
                               char** signature_out);

/**
 * orca_identity_verify_message - Verify message signature
 * @param identity: Identity to verify against
 * @param message: Original message
 * @param signature: Base64 encoded signature
 * @return: true if verified, false otherwise
 */
bool orca_identity_verify_message(OrcaIdentity* identity, const char* message,
                                  const char* signature);

/* ============================================================================
 * IDENTITY QUERY FUNCTIONS
 * ============================================================================ */

/**
 * orca_identity_get_id - Get human-readable ID from identity
 * @param identity: Identity
 * @param id_out: Output buffer (must be at least ORCA_ID_LEN)
 * @return: Pointer to id_out
 */
char* orca_identity_get_id(OrcaIdentity* identity, char* id_out);

/**
 * orca_identity_get_public_key - Get public key from identity
 * @param identity: Identity
 * @param key_out: Output buffer (must be at least ORCA_PUBKEY_LEN)
 * @return: Pointer to key_out
 */
char* orca_identity_get_public_key(OrcaIdentity* identity, char* key_out);

/**
 * orca_identity_is_secure - Check if identity is secure mode
 * @param identity: Identity
 * @return: true if secure, false otherwise
 */
bool orca_identity_is_secure(OrcaIdentity* identity);

/**
 * orca_identity_is_normal - Check if identity is normal mode
 * @param identity: Identity
 * @return: true if normal, false otherwise
 */
bool orca_identity_is_normal(OrcaIdentity* identity);

/* ============================================================================
 * IDENTITY CONVERSION FUNCTIONS
 * ============================================================================ */

/**
 * orca_identity_from_json - Parse identity from JSON string
 * @param json: JSON string
 * @param identity_out: Output identity
 * @return: 0 on success, -1 on failure
 */
int orca_identity_from_json(const char* json, OrcaIdentity* identity_out);

/**
 * orca_identity_to_json - Convert identity to JSON string
 * @param identity: Identity
 * @param json_out: Output JSON string (must be freed by caller)
 * @return: 0 on success, -1 on failure
 */
int orca_identity_to_json(OrcaIdentity* identity, char** json_out);

/**
 * orca_identity_to_json_pretty - Convert identity to pretty JSON
 * @param identity: Identity
 * @param json_out: Output JSON string (must be freed by caller)
 * @return: 0 on success, -1 on failure
 */
int orca_identity_to_json_pretty(OrcaIdentity* identity, char** json_out);

/* ============================================================================
 * IDENTITY UTILITY FUNCTIONS
 * ============================================================================ */

/**
 * orca_identity_generate_id - Generate a unique ID from public key
 * @param public_key: RSA public key in PEM format
 * @param prefix: Optional prefix (e.g., "ORCA-")
 * @param id_out: Output buffer (must be at least ORCA_ID_LEN)
 * @return: Pointer to id_out
 */
char* orca_identity_generate_id(const char* public_key, const char* prefix,
                                char* id_out);

/**
 * orca_identity_generate_normal_id - Generate a 3-digit ID
 * @param id_out: Output buffer (must be at least 16 bytes)
 * @return: Pointer to id_out
 */
char* orca_identity_generate_normal_id(char* id_out);

/**
 * orca_identity_is_valid_id - Check if ID is valid
 * @param id: ID to check
 * @return: true if valid, false otherwise
 */
bool orca_identity_is_valid_id(const char* id);

/**
 * orca_identity_print - Print identity to stdout
 * @param identity: Identity to print
 */
void orca_identity_print(OrcaIdentity* identity);

/**
 * orca_identity_print_short - Print short identity summary
 * @param identity: Identity to print
 */
void orca_identity_print_short(OrcaIdentity* identity);

/* ============================================================================
 * IDENTITY STORAGE FUNCTIONS
 * ============================================================================ */

/**
 * orca_identity_storage_init - Initialize identity storage directory
 * @return: 0 on success, -1 on failure
 */
int orca_identity_storage_init(void);

/**
 * orca_identity_storage_cleanup - Cleanup identity storage
 * @return: 0 on success, -1 on failure
 */
int orca_identity_storage_cleanup(void);

/**
 * orca_identity_list - List all stored identities
 * @param identities: Array of identity IDs (must be freed)
 * @param count: Number of identities found
 * @return: 0 on success, -1 on failure
 */
int orca_identity_list(char*** identities, int* count);

/**
 * orca_identity_free_list - Free identity list
 * @param identities: Identity list to free
 * @param count: Number of identities
 */
void orca_identity_free_list(char** identities, int count);

/* ============================================================================
 * IDENTITY PASSCODE FUNCTIONS
 * ============================================================================ */

/**
 * orca_identity_change_passcode - Change identity passcode
 * @param id: Identity ID
 * @param old_passcode: Current passcode
 * @param new_passcode: New passcode
 * @return: 0 on success, -1 on failure
 */
int orca_identity_change_passcode(const char* id, const char* old_passcode,
                                  const char* new_passcode);

/**
 * orca_identity_check_passcode - Check if passcode is valid
 * @param identity: Identity
 * @param passcode: Passcode to check
 * @return: true if valid, false otherwise
 */
bool orca_identity_check_passcode(OrcaIdentity* identity, const char* passcode);

/**
 * orca_identity_derive_key - Derive AES key from passcode
 * @param identity: Identity (for salt)
 * @param passcode: Passcode
 * @param key_out: Output key (must be 32 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_identity_derive_key(OrcaIdentity* identity, const char* passcode,
                             unsigned char* key_out);

/**
 * orca_identity_derive_key_hex - Derive AES key as hex
 * @param identity: Identity (for salt)
 * @param passcode: Passcode
 * @param key_hex_out: Output hex key (must be 65 bytes)
 * @return: 0 on success, -1 on failure
 */
int orca_identity_derive_key_hex(OrcaIdentity* identity, const char* passcode,
                                 char* key_hex_out);

/* ============================================================================
 * IDENTITY COMPARISON FUNCTIONS
 * ============================================================================ */

/**
 * orca_identity_compare - Compare two identities
 * @param identity1: First identity
 * @param identity2: Second identity
 * @return: 0 if equal, -1 if different
 */
int orca_identity_compare(OrcaIdentity* identity1, OrcaIdentity* identity2);

/**
 * orca_identity_compare_by_id - Compare identities by ID
 * @param id1: First ID
 * @param id2: Second ID
 * @return: 0 if equal, -1 if different
 */
int orca_identity_compare_by_id(const char* id1, const char* id2);

/**
 * orca_identity_matches_id - Check if identity matches ID
 * @param identity: Identity
 * @param id: ID to check
 * @return: true if matches, false otherwise
 */
bool orca_identity_matches_id(OrcaIdentity* identity, const char* id);

/* ============================================================================
 * IDENTITY DEBUG FUNCTIONS
 * ============================================================================ */

/**
 * orca_identity_debug_dump - Dump identity debug info
 * @param identity: Identity
 * @param fp: File pointer to dump to (stderr if NULL)
 */
void orca_identity_debug_dump(OrcaIdentity* identity, FILE* fp);

/**
 * orca_identity_debug_verify_storage - Verify storage integrity
 * @return: 0 on success, -1 on failure
 */
int orca_identity_debug_verify_storage(void);

#ifdef __cplusplus
}
#endif

#endif /* ORCA_IDENTITY_H */
