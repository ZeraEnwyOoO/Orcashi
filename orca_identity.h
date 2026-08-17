 // orca_identity.h - Full version with 3-digit secure identity support
#ifndef ORCA_IDENTITY_H
#define ORCA_IDENTITY_H

#include "orca_crypto.h"
#include <stdbool.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

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

typedef enum {
    ORCA_IDENTITY_MODE_NORMAL = 0,
    ORCA_IDENTITY_MODE_SECURE = 1
} OrcaIdentityMode;

typedef struct {
    char id[ORCA_ID_LEN];
    char name[ORCA_NAME_LEN];
    char role[ORCA_ROLE_LEN];
    OrcaIdentityMode mode;
    time_t created_at;
    time_t last_used;
    bool verified;
    char public_key[ORCA_PUBKEY_LEN];
    char private_key_encrypted[ORCA_ENCRYPTED_LEN];
    char signature[ORCA_SIG_LEN];
    char salt_hex[ORCA_SALT_LEN * 2 + 1];
    char version[16];
} OrcaIdentity;

typedef struct {
    OrcaIdentity identities[10];
    int count;
    char default_id[ORCA_ID_LEN];
} OrcaIdentityStore;

/* ============================================================================
 * IDENTITY CREATION
 * ============================================================================ */

int orca_identity_create(const char* name, const char* passcode,
                         const char* role, OrcaIdentity* identity_out);

int orca_identity_create_normal(const char* id, const char* ip,
                                OrcaIdentity* identity_out);

/* ===== NEW: 3-digit secure identity with RSA keypair =====
 *
 * Creates a secure identity with:
 *   - RSA 2048-bit keypair
 *   - 3-digit ID (e.g., "<075>") - user provided
 *   - Encrypted private key (AES-256-CBC + PBKDF2)
 *   - Digital signature covering: id|name|role|created_at
 *
 * The ID is cryptographically bound to the public key via signature.
 * Password is NOT stored - only used to derive encryption key.
 *
 * @param id          3-digit ID format: "<075>"
 * @param passcode    User passcode (min 8 chars) - NOT stored
 * @param name        Display name (optional, can be NULL)
 * @param role        Role (optional, can be NULL, defaults to "user")
 * @param identity_out Output identity structure
 * @return 0 on success, -1 on error
 */
int orca_identity_create_secure_3digit(const char* id, const char* passcode,
                                       const char* name, const char* role,
                                       OrcaIdentity* identity_out);

/* ============================================================================
 * IDENTITY LOADING
 * ============================================================================ */

int orca_identity_load(OrcaIdentity* identity_out, const char* passcode);
int orca_identity_load_by_id(const char* id, OrcaIdentity* identity_out,
                             const char* passcode);

/* ============================================================================
 * IDENTITY STORAGE
 * ============================================================================ */

int orca_identity_save(OrcaIdentity* identity);
int orca_identity_delete(const char* id);
bool orca_identity_exists(const char* id);
int orca_identity_get_default(char* id_out);
int orca_identity_set_default(const char* id);
int orca_identity_reset(bool force);

/* ============================================================================
 * IDENTITY VERIFICATION
 * ============================================================================ */

bool orca_identity_verify(OrcaIdentity* identity);
bool orca_identity_verify_with_passcode(OrcaIdentity* identity,
                                        const char* passcode);

/* ============================================================================
 * IDENTITY SIGNING
 * ============================================================================ */

int orca_identity_sign_message(OrcaIdentity* identity, const char* message,
                               char** signature_out);
bool orca_identity_verify_message(OrcaIdentity* identity, const char* message,
                                  const char* signature);

/* ============================================================================
 * IDENTITY QUERY
 * ============================================================================ */

char* orca_identity_get_id(OrcaIdentity* identity, char* id_out);
char* orca_identity_get_public_key(OrcaIdentity* identity, char* key_out);
bool orca_identity_is_secure(OrcaIdentity* identity);
bool orca_identity_is_normal(OrcaIdentity* identity);

/* ============================================================================
 * IDENTITY JSON CONVERSION
 * ============================================================================ */

int orca_identity_from_json(const char* json, OrcaIdentity* identity_out);
int orca_identity_to_json(OrcaIdentity* identity, char** json_out);
int orca_identity_to_json_pretty(OrcaIdentity* identity, char** json_out);

/* ============================================================================
 * ID GENERATION
 * ============================================================================ */

char* orca_identity_generate_id(const char* public_key, const char* prefix,
                                char* id_out);
char* orca_identity_generate_normal_id(char* id_out);
bool orca_identity_is_valid_id(const char* id);

/* ============================================================================
 * IDENTITY DISPLAY
 * ============================================================================ */

void orca_identity_print(OrcaIdentity* identity);
void orca_identity_print_short(OrcaIdentity* identity);

/* ============================================================================
 * IDENTITY STORAGE MANAGEMENT
 * ============================================================================ */

int orca_identity_storage_init(void);
int orca_identity_storage_cleanup(void);
int orca_identity_list(char*** identities, int* count);
void orca_identity_free_list(char** identities, int count);

/* ============================================================================
 * PASSCODE MANAGEMENT
 * ============================================================================ */

int orca_identity_change_passcode(const char* id, const char* old_passcode,
                                  const char* new_passcode);
bool orca_identity_check_passcode(OrcaIdentity* identity, const char* passcode);
int orca_identity_derive_key(OrcaIdentity* identity, const char* passcode,
                             unsigned char* key_out);
int orca_identity_derive_key_hex(OrcaIdentity* identity, const char* passcode,
                                 char* key_hex_out);

/* ============================================================================
 * IDENTITY COMPARISON
 * ============================================================================ */

int orca_identity_compare(OrcaIdentity* identity1, OrcaIdentity* identity2);
int orca_identity_compare_by_id(const char* id1, const char* id2);
bool orca_identity_matches_id(OrcaIdentity* identity, const char* id);

/* ============================================================================
 * DEBUG
 * ============================================================================ */

void orca_identity_debug_dump(OrcaIdentity* identity, FILE* fp);
int orca_identity_debug_verify_storage(void);

/* ============================================================================
 * INTERNAL HELPERS (exported for use by main.c)
 * ============================================================================ */

/* Zeroize memory (secure erase) - for passcode cleanup */
void zeroize(void* ptr, size_t len);

/* Read entire file content into memory (caller must free) */
char* read_file_content(const char* path);

#ifdef __cplusplus
}
#endif

#endif
