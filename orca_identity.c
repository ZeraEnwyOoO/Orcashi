 // orca_identity.c - Full implementation with 3-digit secure identity support
#include "orca_identity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>

/* ============================================================================
 * STATIC HELPERS
 * ============================================================================ */

static void set_identity_error(const char* msg) {
    orca_clear_error();
    fprintf(stderr, "[ORCA IDENTITY ERROR] %s\n", msg);
}

static int ensure_directory(const char* path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        set_identity_error("Path exists but is not a directory");
        return -1;
    }
    
    if (mkdir(path, 0700) != 0) {
        set_identity_error("Failed to create identity directory");
        return -1;
    }
    return 0;
}

static int write_file_content(const char* path, const char* content) {
    FILE* f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "%s", content);
    fclose(f);
    return 0;
}

/* ============================================================================
 * ID NORMALIZATION (for consistent signing/verification)
 * ============================================================================ */

static void normalize_id(const char* input, char* output, size_t out_size) {
    if (!input || !output || out_size == 0) return;
    
    size_t i = 0, j = 0;
    size_t len = strlen(input);
    
    for (i = 0; i < len && j < out_size - 1; i++) {
        if (input[i] != '<' && input[i] != '>') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

/* ============================================================================
 * EXPORTED HELPERS (used by main.c)
 * ============================================================================ */

void zeroize(void* ptr, size_t len) {
    if (ptr && len > 0) {
        volatile char* vptr = (volatile char*)ptr;
        for (size_t i = 0; i < len; i++) {
            vptr[i] = 0;
        }
    }
}

char* read_file_content(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* content = (char*)malloc(len + 1);
    if (!content) {
        fclose(f);
        return NULL;
    }
    
    fread(content, 1, len, f);
    content[len] = '\0';
    fclose(f);
    return content;
}

/* ============================================================================
 * IDENTITY LIFECYCLE FUNCTIONS
 * ============================================================================ */

int orca_identity_create(const char* name, const char* passcode,
                         const char* role, OrcaIdentity* identity_out) {
    if (!passcode || !identity_out) {
        set_identity_error("NULL pointer in orca_identity_create");
        return -1;
    }
    
    if (strlen(passcode) < 8) {
        set_identity_error("Passcode must be at least 8 characters");
        return -1;
    }
    
    memset(identity_out, 0, sizeof(OrcaIdentity));
    
    char* public_key = NULL;
    char* private_key = NULL;
    if (orca_rsa_generate_keypair(&public_key, &private_key) < 0) {
        set_identity_error("Failed to generate RSA keypair");
        return -1;
    }
    
    char salt_hex[33];
    if (orca_generate_salt_hex(salt_hex) < 0) {
        free(public_key);
        free(private_key);
        set_identity_error("Failed to generate salt");
        return -1;
    }
    strcpy(identity_out->salt_hex, salt_hex);
    
    unsigned char key[ORCA_AES_KEY_LEN];
    if (orca_derive_key_from_passcode_hex(passcode, salt_hex,
                                          ORCA_PBKDF2_ITERATIONS, (char*)key) < 0) {
        free(public_key);
        free(private_key);
        set_identity_error("Failed to derive key from passcode");
        return -1;
    }
    
    unsigned char iv[ORCA_AES_IV_LEN];
    unsigned char* ciphertext;
    size_t ciphertext_len;
    if (orca_aes_cbc_encrypt((const unsigned char*)private_key, strlen(private_key),
                             key, iv, &ciphertext, &ciphertext_len) < 0) {
        free(public_key);
        free(private_key);
        set_identity_error("Failed to encrypt private key");
        return -1;
    }
    
    char combined[ORCA_ENCRYPTED_LEN];
    char iv_hex[33];
    orca_bytes_to_hex(iv, ORCA_AES_IV_LEN, iv_hex);
    char* ciphertext_b64 = orca_base64_encode(ciphertext, ciphertext_len);
    snprintf(combined, sizeof(combined), "%s:%s", iv_hex, ciphertext_b64);
    free(ciphertext);
    free(ciphertext_b64);
    
    if (name) {
        strncpy(identity_out->name, name, ORCA_NAME_LEN - 1);
        identity_out->name[ORCA_NAME_LEN - 1] = '\0';
    }
    if (role) {
        strncpy(identity_out->role, role, ORCA_ROLE_LEN - 1);
        identity_out->role[ORCA_ROLE_LEN - 1] = '\0';
    } else {
        strcpy(identity_out->role, "user");
    }
    
    strcpy(identity_out->public_key, public_key);
    strcpy(identity_out->private_key_encrypted, combined);
    identity_out->mode = ORCA_IDENTITY_MODE_SECURE;
    identity_out->created_at = time(NULL);
    identity_out->last_used = identity_out->created_at;
    identity_out->verified = false;
    strcpy(identity_out->version, ORCA_IDENTITY_VERSION);
    
    orca_identity_generate_id(public_key, "ORCA-", identity_out->id);
    
    char data_to_sign[1024];
    snprintf(data_to_sign, sizeof(data_to_sign), "%s|%s|%s|%ld",
             identity_out->id, identity_out->name, identity_out->role,
             (long)identity_out->created_at);
    
    char* signature = NULL;
    if (orca_rsa_sign_string(data_to_sign, private_key, &signature) < 0) {
        free(public_key);
        free(private_key);
        set_identity_error("Failed to sign identity");
        return -1;
    }
    strcpy(identity_out->signature, signature);
    free(signature);
    
    if (!orca_identity_verify(identity_out)) {
        free(public_key);
        free(private_key);
        set_identity_error("Identity verification failed after creation");
        return -1;
    }
    identity_out->verified = true;
    
    free(public_key);
    free(private_key);
    return 0;
}

/* ============================================================================
 * NEW: 3-DIGIT SECURE IDENTITY CREATION - FIXED with normalize_id
 * ============================================================================ */

int orca_identity_create_secure_3digit(const char* id, const char* passcode,
                                       const char* name, const char* role,
                                       OrcaIdentity* identity_out) {
    if (!id || !passcode || !identity_out) {
        set_identity_error("NULL pointer in orca_identity_create_secure_3digit");
        return -1;
    }
    
    /* Validate 3-digit ID format: "<075>" */
    if (strlen(id) != 5 || id[0] != '<' || id[4] != '>' ||
        !isdigit(id[1]) || !isdigit(id[2]) || !isdigit(id[3])) {
        set_identity_error("Invalid 3-digit ID format. Use '<XXX>' where X is digit");
        return -1;
    }
    
    if (strlen(passcode) < 8) {
        set_identity_error("Passcode must be at least 8 characters");
        return -1;
    }
    
    memset(identity_out, 0, sizeof(OrcaIdentity));
    
    /* 1. Generate RSA keypair */
    char* public_key = NULL;
    char* private_key = NULL;
    if (orca_rsa_generate_keypair(&public_key, &private_key) < 0) {
        set_identity_error("Failed to generate RSA keypair");
        return -1;
    }
    
    /* 2. Generate salt for KDF */
    char salt_hex[33];
    if (orca_generate_salt_hex(salt_hex) < 0) {
        free(public_key);
        free(private_key);
        set_identity_error("Failed to generate salt");
        return -1;
    }
    strcpy(identity_out->salt_hex, salt_hex);
    
    /* 3. Derive encryption key from passcode */
    unsigned char key[ORCA_AES_KEY_LEN];
    if (orca_derive_key_from_passcode_hex(passcode, salt_hex,
                                          ORCA_PBKDF2_ITERATIONS, (char*)key) < 0) {
        free(public_key);
        free(private_key);
        zeroize(key, ORCA_AES_KEY_LEN);
        set_identity_error("Failed to derive key from passcode");
        return -1;
    }
    
    /* 4. Encrypt private key with AES-256-CBC */
    unsigned char iv[ORCA_AES_IV_LEN];
    unsigned char* ciphertext = NULL;
    size_t ciphertext_len = 0;
    if (orca_aes_cbc_encrypt((const unsigned char*)private_key, strlen(private_key),
                             key, iv, &ciphertext, &ciphertext_len) < 0) {
        free(public_key);
        free(private_key);
        zeroize(key, ORCA_AES_KEY_LEN);
        set_identity_error("Failed to encrypt private key");
        return -1;
    }
    zeroize(key, ORCA_AES_KEY_LEN);
    
    char combined[ORCA_ENCRYPTED_LEN];
    char iv_hex[33];
    orca_bytes_to_hex(iv, ORCA_AES_IV_LEN, iv_hex);
    char* ciphertext_b64 = orca_base64_encode(ciphertext, ciphertext_len);
    snprintf(combined, sizeof(combined), "%s:%s", iv_hex, ciphertext_b64);
    free(ciphertext);
    free(ciphertext_b64);
    
    /* 5. Set identity fields */
    strcpy(identity_out->id, id);
    
    if (name) {
        strncpy(identity_out->name, name, ORCA_NAME_LEN - 1);
        identity_out->name[ORCA_NAME_LEN - 1] = '\0';
    } else {
        strcpy(identity_out->name, "orcashi");
    }
    
    if (role) {
        strncpy(identity_out->role, role, ORCA_ROLE_LEN - 1);
        identity_out->role[ORCA_ROLE_LEN - 1] = '\0';
    } else {
        strcpy(identity_out->role, "user");
    }
    
    strcpy(identity_out->public_key, public_key);
    strcpy(identity_out->private_key_encrypted, combined);
    identity_out->mode = ORCA_IDENTITY_MODE_SECURE;
    identity_out->created_at = time(NULL);
    identity_out->last_used = identity_out->created_at;
    identity_out->verified = false;
    strcpy(identity_out->version, ORCA_IDENTITY_VERSION);
    
    /* DEBUG: Print created_at when creating identity */
    printf("[DEBUG] ========================================\n");
    printf("[DEBUG] Creating identity\n");
    printf("[DEBUG] ID: %s\n", id);
    printf("[DEBUG] Name: %s\n", name ? name : "NULL");
    printf("[DEBUG] created_at: %ld\n", (long)identity_out->created_at);
    printf("[DEBUG] public_key length: %zu\n", strlen(identity_out->public_key));
    printf("[DEBUG] ========================================\n");
    
    /* 6. Sign identity data - FIX: Normalize ID before signing */
    char norm_id[64];
    normalize_id(identity_out->id, norm_id, sizeof(norm_id));
    
    char data_to_sign[1024];
    snprintf(data_to_sign, sizeof(data_to_sign), "%s|%s|%s|%ld",
             norm_id, identity_out->name, identity_out->role,
             (long)identity_out->created_at);
    
    printf("[DEBUG] ========================================\n");
    printf("[DEBUG] Signing identity\n");
    printf("[DEBUG] Data to sign (normalized): '%s'\n", data_to_sign);
    printf("[DEBUG] Private key length: %zu\n", strlen(private_key));
    printf("[DEBUG] Private key (first 50): %.50s...\n", private_key);
    printf("[DEBUG] ========================================\n");
    
    char* signature = NULL;
    if (orca_rsa_sign_string(data_to_sign, private_key, &signature) < 0) {
        free(public_key);
        free(private_key);
        set_identity_error("Failed to sign identity");
        return -1;
    }
    strcpy(identity_out->signature, signature);
    free(signature);
    
    printf("[DEBUG] Signature created, length: %zu\n", strlen(identity_out->signature));
    printf("[DEBUG] Signature (first 50): %.50s...\n", identity_out->signature);
    
    /* 7. Verify identity - FIX: Normalize ID before verification */
    char norm_id_verify[64];
    normalize_id(identity_out->id, norm_id_verify, sizeof(norm_id_verify));
    
    char data_to_verify[1024];
    snprintf(data_to_verify, sizeof(data_to_verify), "%s|%s|%s|%ld",
             norm_id_verify, identity_out->name, identity_out->role,
             (long)identity_out->created_at);
    
    printf("[DEBUG] Verifying with data (normalized): '%s'\n", data_to_verify);
    
    if (!orca_rsa_verify_string(data_to_verify, identity_out->signature, identity_out->public_key)) {
        free(public_key);
        free(private_key);
        printf("[DEBUG] Identity verification FAILED after creation!\n");
        set_identity_error("Identity verification failed after creation");
        return -1;
    }
    identity_out->verified = true;
    
    printf("[DEBUG] Identity verified successfully!\n");
    printf("[DEBUG] ========================================\n");
    
    free(public_key);
    free(private_key);
    return 0;
}

int orca_identity_create_normal(const char* id, const char* ip,
                                OrcaIdentity* identity_out) {
    if (!id || !ip || !identity_out) {
        set_identity_error("NULL pointer in orca_identity_create_normal");
        return -1;
    }
    
    memset(identity_out, 0, sizeof(OrcaIdentity));
    strncpy(identity_out->id, id, ORCA_ID_LEN - 1);
    identity_out->id[ORCA_ID_LEN - 1] = '\0';
    identity_out->mode = ORCA_IDENTITY_MODE_NORMAL;
    identity_out->created_at = time(NULL);
    identity_out->last_used = identity_out->created_at;
    identity_out->verified = true;
    strcpy(identity_out->version, ORCA_IDENTITY_VERSION);
    strcpy(identity_out->role, "user");
    
    return 0;
}

int orca_identity_load(OrcaIdentity* identity_out, const char* passcode) {
    if (!identity_out) {
        set_identity_error("NULL pointer in orca_identity_load");
        return -1;
    }
    
    char* json = read_file_content(ORCA_IDENTITY_FILE);
    if (!json) {
        set_identity_error("No identity file found");
        return -1;
    }
    
    if (orca_identity_from_json(json, identity_out) < 0) {
        free(json);
        set_identity_error("Failed to parse identity JSON");
        return -1;
    }
    free(json);
    
    if (identity_out->mode == ORCA_IDENTITY_MODE_SECURE) {
        if (!passcode) {
            set_identity_error("Passcode required for secure identity");
            return -1;
        }
        
        if (!orca_identity_verify_with_passcode(identity_out, passcode)) {
            set_identity_error("Failed to verify identity with passcode");
            return -1;
        }
        identity_out->verified = true;
    } else {
        identity_out->verified = true;
    }
    
    identity_out->last_used = time(NULL);
    
    /* DEBUG: Print loaded identity info */
    printf("[DEBUG] ========================================\n");
    printf("[DEBUG] Loaded identity\n");
    printf("[DEBUG] ID: %s\n", identity_out->id);
    printf("[DEBUG] Name: %s\n", identity_out->name);
    printf("[DEBUG] created_at: %ld\n", (long)identity_out->created_at);
    printf("[DEBUG] public_key length: %zu\n", strlen(identity_out->public_key));
    printf("[DEBUG] signature length: %zu\n", strlen(identity_out->signature));
    printf("[DEBUG] signature (first 50): %.50s...\n", identity_out->signature);
    printf("[DEBUG] ========================================\n");
    
    return 0;
}

int orca_identity_load_by_id(const char* id, OrcaIdentity* identity_out,
                             const char* passcode) {
    if (!id || !identity_out) {
        set_identity_error("NULL pointer in orca_identity_load_by_id");
        return -1;
    }
    
    char** identities = NULL;
    int count = 0;
    if (orca_identity_list(&identities, &count) < 0) {
        return -1;
    }
    
    int found = -1;
    for (int i = 0; i < count; i++) {
        if (strcmp(identities[i], id) == 0) {
            found = i;
            break;
        }
    }
    
    if (found < 0) {
        orca_identity_free_list(identities, count);
        set_identity_error("Identity ID not found");
        return -1;
    }
    
    char path[512];
    snprintf(path, sizeof(path), "%s%s/identity.json", ORCA_IDENTITY_HOME, id);
    char* json = read_file_content(path);
    orca_identity_free_list(identities, count);
    
    if (!json) {
        set_identity_error("Failed to read identity file");
        return -1;
    }
    
    if (orca_identity_from_json(json, identity_out) < 0) {
        free(json);
        set_identity_error("Failed to parse identity JSON");
        return -1;
    }
    free(json);
    
    if (identity_out->mode == ORCA_IDENTITY_MODE_SECURE) {
        if (!passcode) {
            set_identity_error("Passcode required for secure identity");
            return -1;
        }
        if (!orca_identity_verify_with_passcode(identity_out, passcode)) {
            set_identity_error("Failed to verify identity with passcode");
            return -1;
        }
        identity_out->verified = true;
    } else {
        identity_out->verified = true;
    }
    
    identity_out->last_used = time(NULL);
    return 0;
}

int orca_identity_save(OrcaIdentity* identity) {
    if (!identity) {
        set_identity_error("NULL pointer in orca_identity_save");
        return -1;
    }
    
    if (ensure_directory(ORCA_IDENTITY_HOME) < 0) {
        return -1;
    }
    
    char* json = NULL;
    if (orca_identity_to_json(identity, &json) < 0) {
        set_identity_error("Failed to convert identity to JSON");
        return -1;
    }
    
    if (write_file_content(ORCA_IDENTITY_FILE, json) < 0) {
        free(json);
        set_identity_error("Failed to write identity file");
        return -1;
    }
    free(json);
    
    if (write_file_content(ORCA_PUBLIC_KEY_FILE, identity->public_key) < 0) {
        set_identity_error("Failed to write public key file");
        return -1;
    }
    
    if (identity->mode == ORCA_IDENTITY_MODE_SECURE) {
        if (write_file_content(ORCA_PRIVATE_KEY_FILE, identity->private_key_encrypted) < 0) {
            set_identity_error("Failed to write private key file");
            return -1;
        }
        if (write_file_content(ORCA_SIGNATURE_FILE, identity->signature) < 0) {
            set_identity_error("Failed to write signature file");
            return -1;
        }
        if (write_file_content(ORCA_SALT_FILE, identity->salt_hex) < 0) {
            set_identity_error("Failed to write salt file");
            return -1;
        }
    }
    
    return 0;
}

int orca_identity_delete(const char* id) {
    if (!id) {
        set_identity_error("NULL pointer in orca_identity_delete");
        return -1;
    }
    
    char path[512];
    snprintf(path, sizeof(path), "%s%s", ORCA_IDENTITY_HOME, id);
    
    struct stat st;
    if (stat(path, &st) != 0) {
        set_identity_error("Identity not found");
        return -1;
    }
    
    DIR* dir = opendir(path);
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            char filepath[512];
            snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);
            unlink(filepath);
        }
        closedir(dir);
    }
    
    rmdir(path);
    return 0;
}

bool orca_identity_exists(const char* id) {
    if (id) {
        char path[512];
        snprintf(path, sizeof(path), "%s%s/identity.json", ORCA_IDENTITY_HOME, id);
        struct stat st;
        return (stat(path, &st) == 0);
    } else {
        struct stat st;
        return (stat(ORCA_IDENTITY_FILE, &st) == 0);
    }
}

int orca_identity_get_default(char* id_out) {
    if (!id_out) {
        set_identity_error("NULL pointer in orca_identity_get_default");
        return -1;
    }
    
    char* json = read_file_content(ORCA_METADATA_FILE);
    if (!json) {
        set_identity_error("No metadata file found");
        return -1;
    }
    
    const char* pos = strstr(json, "\"default_id\":\"");
    if (!pos) {
        free(json);
        set_identity_error("No default_id in metadata");
        return -1;
    }
    
    pos += 14;
    const char* end = strchr(pos, '"');
    if (!end) {
        free(json);
        set_identity_error("Malformed metadata");
        return -1;
    }
    
    int len = end - pos;
    if (len >= ORCA_ID_LEN) len = ORCA_ID_LEN - 1;
    strncpy(id_out, pos, len);
    id_out[len] = '\0';
    free(json);
    return 0;
}

int orca_identity_set_default(const char* id) {
    if (!id) {
        set_identity_error("NULL pointer in orca_identity_set_default");
        return -1;
    }
    
    if (!orca_identity_exists(id)) {
        set_identity_error("Identity does not exist");
        return -1;
    }
    
    char metadata[256];
    snprintf(metadata, sizeof(metadata), "{\"default_id\":\"%s\"}", id);
    
    if (ensure_directory(ORCA_IDENTITY_HOME) < 0) {
        return -1;
    }
    
    return write_file_content(ORCA_METADATA_FILE, metadata);
}

/* ============================================================================
 * IDENTITY VERIFICATION FUNCTIONS - FIXED with normalize_id
 * ============================================================================ */

bool orca_identity_verify(OrcaIdentity* identity) {
    if (!identity) return false;
    
    if (identity->mode == ORCA_IDENTITY_MODE_NORMAL) {
        return true;
    }
    
    /* FIX: Normalize ID before verification */
    char norm_id[64];
    normalize_id(identity->id, norm_id, sizeof(norm_id));
    
    char data_to_verify[1024];
    snprintf(data_to_verify, sizeof(data_to_verify), "%s|%s|%s|%ld",
             norm_id, identity->name, identity->role,
             (long)identity->created_at);
    
    printf("[DEBUG] Verifying (normalized): '%s'\n", data_to_verify);
    
    return orca_rsa_verify_string(data_to_verify, identity->signature,
                                  identity->public_key);
}

bool orca_identity_verify_with_passcode(OrcaIdentity* identity,
                                        const char* passcode) {
    if (!identity || !passcode) return false;
    
    unsigned char key[ORCA_AES_KEY_LEN];
    if (orca_derive_key_from_passcode_hex(passcode, identity->salt_hex,
                                          ORCA_PBKDF2_ITERATIONS, (char*)key) < 0) {
        return false;
    }
    
    char* private_key = NULL;
    char iv_hex[33];
    char ciphertext_b64[ORCA_ENCRYPTED_LEN];
    
    char* colon = strchr(identity->private_key_encrypted, ':');
    if (!colon) {
        zeroize(key, ORCA_AES_KEY_LEN);
        return false;
    }
    
    int iv_len = colon - identity->private_key_encrypted;
    if (iv_len >= 33) {
        zeroize(key, ORCA_AES_KEY_LEN);
        return false;
    }
    strncpy(iv_hex, identity->private_key_encrypted, iv_len);
    iv_hex[iv_len] = '\0';
    strcpy(ciphertext_b64, colon + 1);
    
    char key_hex[65];
    orca_bytes_to_hex(key, ORCA_AES_KEY_LEN, key_hex);
    
    if (orca_aes_cbc_decrypt_string(ciphertext_b64, iv_hex, key_hex, &private_key) < 0) {
        zeroize(key_hex, sizeof(key_hex));
        zeroize(key, ORCA_AES_KEY_LEN);
        return false;
    }
    zeroize(key_hex, sizeof(key_hex));
    zeroize(key, ORCA_AES_KEY_LEN);
    
    char test_data[] = "test";
    char* signature = NULL;
    if (orca_rsa_sign_string(test_data, private_key, &signature) < 0) {
        free(private_key);
        return false;
    }
    
    bool result = orca_rsa_verify_string(test_data, signature, identity->public_key);
    free(signature);
    free(private_key);
    
    return result;
}

int orca_identity_sign_message(OrcaIdentity* identity, const char* message,
                               char** signature_out) {
    if (!identity || !message || !signature_out) {
        set_identity_error("NULL pointer in orca_identity_sign_message");
        return -1;
    }
    
    if (identity->mode == ORCA_IDENTITY_MODE_NORMAL) {
        set_identity_error("Cannot sign with normal identity");
        return -1;
    }
    
    char iv_hex[33];
    char ciphertext_b64[ORCA_ENCRYPTED_LEN];
    char* colon = strchr(identity->private_key_encrypted, ':');
    if (!colon) {
        set_identity_error("Malformed encrypted private key");
        return -1;
    }
    
    int iv_len = colon - identity->private_key_encrypted;
    strncpy(iv_hex, identity->private_key_encrypted, iv_len);
    iv_hex[iv_len] = '\0';
    strcpy(ciphertext_b64, colon + 1);
    
    set_identity_error("Private key decryption requires passcode");
    return -1;
}

bool orca_identity_verify_message(OrcaIdentity* identity, const char* message,
                                  const char* signature) {
    if (!identity || !message || !signature) return false;
    
    if (identity->mode == ORCA_IDENTITY_MODE_NORMAL) {
        return true;
    }
    
    return orca_rsa_verify_string(message, signature, identity->public_key);
}

/* ============================================================================
 * IDENTITY QUERY FUNCTIONS
 * ============================================================================ */

char* orca_identity_get_id(OrcaIdentity* identity, char* id_out) {
    if (!identity || !id_out) return NULL;
    strcpy(id_out, identity->id);
    return id_out;
}

char* orca_identity_get_public_key(OrcaIdentity* identity, char* key_out) {
    if (!identity || !key_out) return NULL;
    strcpy(key_out, identity->public_key);
    return key_out;
}

bool orca_identity_is_secure(OrcaIdentity* identity) {
    return identity && identity->mode == ORCA_IDENTITY_MODE_SECURE;
}

bool orca_identity_is_normal(OrcaIdentity* identity) {
    return identity && identity->mode == ORCA_IDENTITY_MODE_NORMAL;
}

/* ============================================================================
 * IDENTITY CONVERSION FUNCTIONS
 * ============================================================================ */

int orca_identity_from_json(const char* json, OrcaIdentity* identity_out) {
    if (!json || !identity_out) {
        set_identity_error("NULL pointer in orca_identity_from_json");
        return -1;
    }
    
    memset(identity_out, 0, sizeof(OrcaIdentity));
    
    const char* pos = strstr(json, "\"id\"");
    if (pos) {
        pos = strchr(pos, ':');
        if (pos) {
            pos++;
            while (*pos == ' ' || *pos == '\t') pos++;
            if (*pos == '"') {
                pos++;
                const char* end = strchr(pos, '"');
                if (end) {
                    int len = end - pos;
                    if (len < ORCA_ID_LEN) {
                        strncpy(identity_out->id, pos, len);
                        identity_out->id[len] = '\0';
                    }
                }
            }
        }
    }
    
    pos = strstr(json, "\"name\"");
    if (pos) {
        pos = strchr(pos, ':');
        if (pos) {
            pos++;
            while (*pos == ' ' || *pos == '\t') pos++;
            if (*pos == '"') {
                pos++;
                const char* end = strchr(pos, '"');
                if (end) {
                    int len = end - pos;
                    if (len < ORCA_NAME_LEN) {
                        strncpy(identity_out->name, pos, len);
                        identity_out->name[len] = '\0';
                    }
                }
            }
        }
    }
    
    pos = strstr(json, "\"role\"");
    if (pos) {
        pos = strchr(pos, ':');
        if (pos) {
            pos++;
            while (*pos == ' ' || *pos == '\t') pos++;
            if (*pos == '"') {
                pos++;
                const char* end = strchr(pos, '"');
                if (end) {
                    int len = end - pos;
                    if (len < ORCA_ROLE_LEN) {
                        strncpy(identity_out->role, pos, len);
                        identity_out->role[len] = '\0';
                    }
                }
            }
        }
    }
    
    pos = strstr(json, "\"mode\"");
    if (pos) {
        pos = strchr(pos, ':');
        if (pos) {
            pos++;
            while (*pos == ' ' || *pos == '\t') pos++;
            identity_out->mode = atoi(pos);
        }
    }
    
    pos = strstr(json, "\"version\"");
    if (pos) {
        pos = strchr(pos, ':');
        if (pos) {
            pos++;
            while (*pos == ' ' || *pos == '\t') pos++;
            if (*pos == '"') {
                pos++;
                const char* end = strchr(pos, '"');
                if (end) {
                    int len = end - pos;
                    if (len < 16) {
                        strncpy(identity_out->version, pos, len);
                        identity_out->version[len] = '\0';
                    }
                }
            }
        }
    }
    
    pos = strstr(json, "\"created_at\"");
    if (pos) {
        pos = strchr(pos, ':');
        if (pos) {
            pos++;
            while (*pos == ' ' || *pos == '\t') pos++;
            identity_out->created_at = atol(pos);
        }
    }
    
    pos = strstr(json, "\"last_used\"");
    if (pos) {
        pos = strchr(pos, ':');
        if (pos) {
            pos++;
            while (*pos == ' ' || *pos == '\t') pos++;
            identity_out->last_used = atol(pos);
        }
    }
    
    pos = strstr(json, "\"verified\"");
    if (pos) {
        pos = strchr(pos, ':');
        if (pos) {
            pos++;
            while (*pos == ' ' || *pos == '\t') pos++;
            identity_out->verified = (strstr(pos, "true") != NULL);
        }
    }
    
    if (strlen(identity_out->public_key) == 0) {
        char* pubkey = read_file_content(ORCA_PUBLIC_KEY_FILE);
        if (pubkey) {
            strcpy(identity_out->public_key, pubkey);
            free(pubkey);
        }
    }
    
    if (strlen(identity_out->private_key_encrypted) == 0 &&
        identity_out->mode == ORCA_IDENTITY_MODE_SECURE) {
        char* privkey = read_file_content(ORCA_PRIVATE_KEY_FILE);
        if (privkey) {
            strcpy(identity_out->private_key_encrypted, privkey);
            free(privkey);
        }
    }
    
    if (strlen(identity_out->signature) == 0 &&
        identity_out->mode == ORCA_IDENTITY_MODE_SECURE) {
        char* sig = read_file_content(ORCA_SIGNATURE_FILE);
        if (sig) {
            strcpy(identity_out->signature, sig);
            free(sig);
        }
    }
    
    if (strlen(identity_out->salt_hex) == 0 &&
        identity_out->mode == ORCA_IDENTITY_MODE_SECURE) {
        char* salt = read_file_content(ORCA_SALT_FILE);
        if (salt) {
            strcpy(identity_out->salt_hex, salt);
            free(salt);
        }
    }
    
    return 0;
}

int orca_identity_to_json(OrcaIdentity* identity, char** json_out) {
    if (!identity || !json_out) {
        set_identity_error("NULL pointer in orca_identity_to_json");
        return -1;
    }
    
    char buffer[8192];
    snprintf(buffer, sizeof(buffer),
             "{\n"
             "  \"id\": \"%s\",\n"
             "  \"name\": \"%s\",\n"
             "  \"role\": \"%s\",\n"
             "  \"mode\": %d,\n"
             "  \"version\": \"%s\",\n"
             "  \"created_at\": %ld,\n"
             "  \"last_used\": %ld,\n"
             "  \"verified\": %s,\n"
             "  \"public_key\": \"%s\",\n"
             "  \"private_key_encrypted\": \"%s\",\n"
             "  \"signature\": \"%s\",\n"
             "  \"salt_hex\": \"%s\"\n"
             "}",
             identity->id,
             identity->name,
             identity->role,
             identity->mode,
             identity->version,
             (long)identity->created_at,
             (long)identity->last_used,
             identity->verified ? "true" : "false",
             identity->public_key,
             identity->private_key_encrypted,
             identity->signature,
             identity->salt_hex);
    
    *json_out = strdup(buffer);
    return (*json_out) ? 0 : -1;
}

int orca_identity_to_json_pretty(OrcaIdentity* identity, char** json_out) {
    return orca_identity_to_json(identity, json_out);
}

/* ============================================================================
 * IDENTITY UTILITY FUNCTIONS
 * ============================================================================ */

char* orca_identity_generate_id(const char* public_key, const char* prefix,
                                char* id_out) {
    if (!public_key || !id_out) return NULL;
    
    unsigned char hash[ORCA_SHA256_LEN];
    orca_hash_string(public_key, hash);
    
    char hex[ORCA_SHA256_LEN * 2 + 1];
    orca_hash_to_hex(hash, hex);
    
    if (prefix) {
        snprintf(id_out, ORCA_ID_LEN, "%s%.8s", prefix, hex);
    } else {
        snprintf(id_out, ORCA_ID_LEN, "%.8s", hex);
    }
    return id_out;
}

char* orca_identity_generate_normal_id(char* id_out) {
    if (!id_out) return NULL;
    
    srand(time(NULL) ^ getpid());
    int num = (rand() % 999) + 1;
    snprintf(id_out, 16, "<%03d>", num);
    return id_out;
}

bool orca_identity_is_valid_id(const char* id) {
    if (!id) return false;
    size_t len = strlen(id);
    
    if (len == 5 && id[0] == '<' && id[4] == '>') {
        for (int i = 1; i < 4; i++) {
            if (!isdigit(id[i])) return false;
        }
        return true;
    }
    
    if (len >= 12 && strncmp(id, "ORCA-", 5) == 0) {
        for (int i = 5; i < (int)len; i++) {
            if (!isalnum(id[i])) return false;
        }
        return true;
    }
    
    return false;
}

void orca_identity_print(OrcaIdentity* identity) {
    if (!identity) return;
    
    printf("\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|                    ORCA IDENTITY                           |\n");
    printf("+-----------------------------------------------------------+\n");
    printf("|  ID        : %s\n", identity->id);
    printf("|  Name      : %s\n", identity->name[0] ? identity->name : "(none)");
    printf("|  Role      : %s\n", identity->role);
    printf("|  Mode      : %s\n", identity->mode == ORCA_IDENTITY_MODE_SECURE ? "SECURE" : "NORMAL");
    printf("|  Version   : %s\n", identity->version);
    printf("|  Created   : %s", ctime(&identity->created_at));
    printf("|  Last Used : %s", ctime(&identity->last_used));
    printf("|  Verified  : %s\n", identity->verified ? "YES" : "NO");
    printf("|  Public Key: %.50s...\n", identity->public_key);
    if (identity->mode == ORCA_IDENTITY_MODE_SECURE) {
        printf("|  Signature  : %.20s...\n", identity->signature);
    }
    printf("+-----------------------------------------------------------+\n");
}

void orca_identity_print_short(OrcaIdentity* identity) {
    if (!identity) return;
    printf("[%s] %s (%s) %s\n",
           identity->id,
           identity->name[0] ? identity->name : "anonymous",
           identity->mode == ORCA_IDENTITY_MODE_SECURE ? "SECURE" : "NORMAL",
           identity->verified ? "YES" : "NO");
}

/* ============================================================================
 * IDENTITY STORAGE FUNCTIONS
 * ============================================================================ */

int orca_identity_storage_init(void) {
    if (ensure_directory(ORCA_IDENTITY_HOME) < 0) {
        return -1;
    }
    return 0;
}

int orca_identity_storage_cleanup(void) {
    rmdir(ORCA_IDENTITY_HOME);
    return 0;
}

int orca_identity_list(char*** identities, int* count) {
    if (!identities || !count) {
        set_identity_error("NULL pointer in orca_identity_list");
        return -1;
    }
    
    *identities = NULL;
    *count = 0;
    
    DIR* dir = opendir(ORCA_IDENTITY_HOME);
    if (!dir) {
        return 0;
    }
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char path[512];
        snprintf(path, sizeof(path), "%s%s/identity.json", ORCA_IDENTITY_HOME, entry->d_name);
        struct stat st;
        if (stat(path, &st) == 0) {
            (*count)++;
            char** new_list = (char**)realloc(*identities, (*count) * sizeof(char*));
            if (!new_list) {
                orca_identity_free_list(*identities, *count - 1);
                closedir(dir);
                set_identity_error("Memory allocation failed");
                return -1;
            }
            *identities = new_list;
            (*identities)[*count - 1] = strdup(entry->d_name);
        }
    }
    
    closedir(dir);
    return 0;
}

void orca_identity_free_list(char** identities, int count) {
    if (!identities) return;
    for (int i = 0; i < count; i++) {
        free(identities[i]);
    }
    free(identities);
}

/* ============================================================================
 * IDENTITY PASSCODE FUNCTIONS
 * ============================================================================ */

int orca_identity_change_passcode(const char* id, const char* old_passcode,
                                  const char* new_passcode) {
    if (!id || !old_passcode || !new_passcode) {
        set_identity_error("NULL pointer in orca_identity_change_passcode");
        return -1;
    }
    
    if (strlen(new_passcode) < 8) {
        set_identity_error("New passcode must be at least 8 characters");
        return -1;
    }
    
    OrcaIdentity identity;
    if (orca_identity_load_by_id(id, &identity, old_passcode) < 0) {
        set_identity_error("Failed to load identity with old passcode");
        return -1;
    }
    
    char new_salt_hex[33];
    if (orca_generate_salt_hex(new_salt_hex) < 0) {
        set_identity_error("Failed to generate new salt");
        return -1;
    }
    
    unsigned char new_key[ORCA_AES_KEY_LEN];
    if (orca_derive_key_from_passcode_hex(new_passcode, new_salt_hex,
                                          ORCA_PBKDF2_ITERATIONS, (char*)new_key) < 0) {
        set_identity_error("Failed to derive new key");
        return -1;
    }
    
    char old_iv_hex[33];
    char old_cipher_b64[ORCA_ENCRYPTED_LEN];
    char* colon = strchr(identity.private_key_encrypted, ':');
    if (!colon) {
        zeroize(new_key, ORCA_AES_KEY_LEN);
        set_identity_error("Malformed encrypted private key");
        return -1;
    }
    
    int iv_len = colon - identity.private_key_encrypted;
    strncpy(old_iv_hex, identity.private_key_encrypted, iv_len);
    old_iv_hex[iv_len] = '\0';
    strcpy(old_cipher_b64, colon + 1);
    
    char* private_key = NULL;
    if (orca_aes_cbc_decrypt_string(old_cipher_b64, old_iv_hex,
                                    (char*)old_passcode, &private_key) < 0) {
        zeroize(new_key, ORCA_AES_KEY_LEN);
        set_identity_error("Failed to decrypt private key");
        return -1;
    }
    
    unsigned char new_iv[ORCA_AES_IV_LEN];
    unsigned char* new_ciphertext;
    size_t new_ciphertext_len;
    if (orca_aes_cbc_encrypt((const unsigned char*)private_key, strlen(private_key),
                             new_key, new_iv, &new_ciphertext, &new_ciphertext_len) < 0) {
        free(private_key);
        zeroize(new_key, ORCA_AES_KEY_LEN);
        set_identity_error("Failed to re-encrypt private key");
        return -1;
    }
    zeroize(new_key, ORCA_AES_KEY_LEN);
    
    char new_iv_hex[33];
    orca_bytes_to_hex(new_iv, ORCA_AES_IV_LEN, new_iv_hex);
    char* new_cipher_b64 = orca_base64_encode(new_ciphertext, new_ciphertext_len);
    free(new_ciphertext);
    
    snprintf(identity.private_key_encrypted, sizeof(identity.private_key_encrypted),
             "%s:%s", new_iv_hex, new_cipher_b64);
    free(new_cipher_b64);
    strcpy(identity.salt_hex, new_salt_hex);
    
    free(private_key);
    
    if (orca_identity_save(&identity) < 0) {
        set_identity_error("Failed to save updated identity");
        return -1;
    }
    
    return 0;
}

bool orca_identity_check_passcode(OrcaIdentity* identity, const char* passcode) {
    if (!identity || !passcode) return false;
    return orca_identity_verify_with_passcode(identity, passcode);
}

int orca_identity_derive_key(OrcaIdentity* identity, const char* passcode,
                             unsigned char* key_out) {
    if (!identity || !passcode || !key_out) {
        set_identity_error("NULL pointer in orca_identity_derive_key");
        return -1;
    }
    
    if (identity->mode != ORCA_IDENTITY_MODE_SECURE) {
        set_identity_error("Cannot derive key from normal identity");
        return -1;
    }
    
    return orca_derive_key_from_passcode_hex(passcode, identity->salt_hex,
                                             ORCA_PBKDF2_ITERATIONS, (char*)key_out);
}

int orca_identity_derive_key_hex(OrcaIdentity* identity, const char* passcode,
                                 char* key_hex_out) {
    if (!identity || !passcode || !key_hex_out) {
        set_identity_error("NULL pointer in orca_identity_derive_key_hex");
        return -1;
    }
    
    unsigned char key[ORCA_AES_KEY_LEN];
    if (orca_identity_derive_key(identity, passcode, key) < 0) {
        return -1;
    }
    
    orca_bytes_to_hex(key, ORCA_AES_KEY_LEN, key_hex_out);
    return 0;
}

/* ============================================================================
 * IDENTITY COMPARISON FUNCTIONS
 * ============================================================================ */

int orca_identity_compare(OrcaIdentity* identity1, OrcaIdentity* identity2) {
    if (!identity1 || !identity2) return -1;
    return strcmp(identity1->id, identity2->id);
}

int orca_identity_compare_by_id(const char* id1, const char* id2) {
    if (!id1 || !id2) return -1;
    return strcmp(id1, id2);
}

bool orca_identity_matches_id(OrcaIdentity* identity, const char* id) {
    if (!identity || !id) return false;
    return strcmp(identity->id, id) == 0;
}

/* ============================================================================
 * IDENTITY RESET FUNCTION
 * ============================================================================ */

int orca_identity_reset(bool force) {
    if (!force) {
        fprintf(stderr, "ERROR: Use --force to reset identity\n");
        return -1;
    }
    
    printf("WARNING: This will permanently delete your identity!\n");
    printf("Type 'yes' to confirm: ");
    fflush(stdout);
    
    char confirm[16];
    if (!fgets(confirm, sizeof(confirm), stdin)) {
        printf("Cancelled\n");
        return -1;
    }
    confirm[strcspn(confirm, "\n")] = '\0';
    
    if (strcmp(confirm, "yes") != 0) {
        printf("Cancelled\n");
        return -1;
    }
    
    unlink(ORCA_IDENTITY_FILE);
    unlink(ORCA_PUBLIC_KEY_FILE);
    unlink(ORCA_PRIVATE_KEY_FILE);
    unlink(ORCA_SIGNATURE_FILE);
    unlink(ORCA_SALT_FILE);
    unlink(ORCA_METADATA_FILE);
    rmdir(ORCA_IDENTITY_HOME);
    
    printf("Identity reset successfully\n");
    return 0;
}

/* ============================================================================
 * IDENTITY DEBUG FUNCTIONS
 * ============================================================================ */

void orca_identity_debug_dump(OrcaIdentity* identity, FILE* fp) {
    if (!identity) return;
    if (!fp) fp = stderr;
    
    fprintf(fp, "=== ORCA IDENTITY DEBUG ===\n");
    fprintf(fp, "ID: %s\n", identity->id);
    fprintf(fp, "Name: %s\n", identity->name);
    fprintf(fp, "Role: %s\n", identity->role);
    fprintf(fp, "Mode: %d\n", identity->mode);
    fprintf(fp, "Version: %s\n", identity->version);
    fprintf(fp, "Created: %ld\n", (long)identity->created_at);
    fprintf(fp, "Last Used: %ld\n", (long)identity->last_used);
    fprintf(fp, "Verified: %d\n", identity->verified);
    fprintf(fp, "Public Key: %.50s...\n", identity->public_key);
    fprintf(fp, "Encrypted Private Key: %.50s...\n", identity->private_key_encrypted);
    fprintf(fp, "Signature: %.50s...\n", identity->signature);
    fprintf(fp, "Salt Hex: %s\n", identity->salt_hex);
    fprintf(fp, "===========================\n");
}

int orca_identity_debug_verify_storage(void) {
    if (!orca_identity_exists(NULL)) {
        fprintf(stderr, "No identity found\n");
        return -1;
    }
    
    OrcaIdentity identity;
    if (orca_identity_load(&identity, NULL) < 0) {
        fprintf(stderr, "Failed to load identity\n");
        return -1;
    }
    
    if (identity.mode == ORCA_IDENTITY_MODE_SECURE) {
        fprintf(stderr, "Secure identity requires passcode to verify\n");
        return 0;
    }
    
    if (!orca_identity_verify(&identity)) {
        fprintf(stderr, "Identity verification failed\n");
        return -1;
    }
    
    printf("Identity storage is valid\n");
    orca_identity_print_short(&identity);
    return 0;
}
