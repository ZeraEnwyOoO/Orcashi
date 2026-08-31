 #include "p2p_manager.h"
#include "dht_node.h"
#include "state_manager.h"
#include "event_loop.h"
#include "orca_crypto.h"
#include "orca_identity.h"
#include "orcashi.h"
#include "ecdh.h"
#include "aes_gcm.h"
#include "nat_classifier.h"
#include "strategy_selector.h"
#include "parallel_runner.h"
#include "ttl_punch.h"
#include "simultaneous_open.h"
#include "friend_relay.h"
#include "turn_client.h"
#include "upnp_client.h"
#include "port_prediction.h"
#include "punch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>

#define P2P_DEBUG 1

#if P2P_DEBUG
#define PLOG(fmt, ...) \
    do { \
        time_t now = time(NULL); \
        struct tm* tm = localtime(&now); \
        fprintf(stderr, "[P2P] %02d:%02d:%02d " fmt "\n", \
                tm->tm_hour, tm->tm_min, tm->tm_sec, ##__VA_ARGS__); \
        fflush(stderr); \
    } while(0)
#else
#define PLOG(fmt, ...) ((void)0)
#endif

#define P2P_MAX_PEERS 256
#define P2P_HANDSHAKE_TIMEOUT 5
#define P2P_KEEPALIVE_INTERVAL 30
#define P2P_RETRY_INTERVAL 3

int g_p2p_socket = -1;

typedef enum {
    P2P_MSG_TYPE_HANDSHAKE = 1,
    P2P_MSG_TYPE_HANDSHAKE_RESPONSE = 2,
    P2P_MSG_TYPE_DATA = 3,
    P2P_MSG_TYPE_KEEPALIVE = 4,
    P2P_MSG_TYPE_CLOSE = 5,
    P2P_MSG_TYPE_ADD_REQUEST = 6,
    P2P_MSG_TYPE_ACCEPT_CONFIRM = 7,
    P2P_MSG_TYPE_REJECT_CONFIRM = 8
} P2PMessageType;

typedef struct {
    uint32_t magic;
    uint8_t version;
    uint8_t type;
    uint32_t sequence;
    uint32_t timestamp;
    uint32_t payload_len;
    uint8_t payload[];
} P2PMessage;

#define P2P_MAGIC 0x4F524341
#define P2P_PROTOCOL_VERSION 1

static P2PPeer g_peers[P2P_MAX_PEERS];
static int g_peer_count = 0;
static pthread_mutex_t g_p2p_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_initialized = false;
static NATType g_nat_type = NAT_UNKNOWN;
static bool g_has_ipv6 = false;
static bool g_has_upnp = false;
static pthread_t g_listener_thread = 0;
static bool g_listener_running = false;
static pthread_t g_keepalive_thread = 0;
static bool g_keepalive_running = false;
static char g_local_ip[INET_ADDRSTRLEN] = {0};
static int g_p2p_port = P2P_PORT;

static void normalize_id(const char* input, char* output, size_t size);
static P2PPeer* find_peer(const char* id);
static P2PPeer* add_peer(const char* id);
static int send_message(P2PPeer* peer, uint8_t type, const uint8_t* payload, size_t payload_len);
static int process_message(P2PPeer* peer, const P2PMessage* msg, size_t msg_len);
static void* listener_thread(void* arg);
static void* keepalive_thread(void* arg);
static int create_udp_socket(int port);
static int establish_secure_channel(P2PPeer* peer);
static int send_handshake(P2PPeer* peer);
static int handle_handshake(P2PPeer* peer, const P2PMessage* msg);
static int handle_data(P2PPeer* peer, const P2PMessage* msg);
static int handle_add_request(P2PPeer* peer, const P2PMessage* msg);
static int handle_accept_confirm(P2PPeer* peer, const P2PMessage* msg);
static int handle_reject_confirm(P2PPeer* peer, const P2PMessage* msg);
static int generate_session_keys(P2PPeer* peer);

void normalize_id(const char* input, char* output, size_t size) {
    if (!input || !output || size == 0) return;
    
    size_t i = 0, j = 0;
    size_t len = strlen(input);
    
    for (i = 0; i < len && j < size - 1; i++) {
        if (input[i] != '<' && input[i] != '>') {
            output[j++] = input[i];
        }
    }
    output[j] = '\0';
}

P2PPeer* find_peer(const char* id) {
    char norm_id[64];
    normalize_id(id, norm_id, sizeof(norm_id));
    
    pthread_mutex_lock(&g_p2p_mutex);
    
    for (int i = 0; i < g_peer_count; i++) {
        char peer_norm[64];
        normalize_id(g_peers[i].id, peer_norm, sizeof(peer_norm));
        if (strcmp(peer_norm, norm_id) == 0) {
            pthread_mutex_unlock(&g_p2p_mutex);
            return &g_peers[i];
        }
    }
    
    pthread_mutex_unlock(&g_p2p_mutex);
    return NULL;
}

P2PPeer* add_peer(const char* id) {
    char norm_id[64];
    normalize_id(id, norm_id, sizeof(norm_id));
    
    pthread_mutex_lock(&g_p2p_mutex);
    
    for (int i = 0; i < g_peer_count; i++) {
        char peer_norm[64];
        normalize_id(g_peers[i].id, peer_norm, sizeof(peer_norm));
        if (strcmp(peer_norm, norm_id) == 0) {
            pthread_mutex_unlock(&g_p2p_mutex);
            return &g_peers[i];
        }
    }
    
    if (g_peer_count >= P2P_MAX_PEERS) {
        pthread_mutex_unlock(&g_p2p_mutex);
        return NULL;
    }
    
    P2PPeer* peer = &g_peers[g_peer_count++];
    memset(peer, 0, sizeof(P2PPeer));
    strcpy(peer->id, norm_id);
    peer->state = P2P_STATE_DISCONNECTED;
    peer->udp_socket = -1;
    peer->created_at = time(NULL);
    peer->last_activity = time(NULL);
    peer->nat_type = NAT_UNKNOWN;
    peer->send_nonce = (uint64_t)time(NULL) ^ (uint64_t)getpid();
    peer->recv_nonce = (uint64_t)time(NULL) ^ (uint64_t)getpid() ^ 0xDEADBEEF;
    
    pthread_mutex_unlock(&g_p2p_mutex);
    return peer;
}

int create_udp_socket(int port) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        PLOG("Failed to create UDP socket: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        PLOG("Failed to bind UDP socket on port %d: %s", port, strerror(errno));
        close(sock);
        return -1;
    }
    
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    return sock;
}

int p2p_init(void) {
    if (g_initialized) return 0;
    
    PLOG("Initializing P2P manager");
    
    char* local_ip = orcashi_get_local_ip();
    if (local_ip) {
        strcpy(g_local_ip, local_ip);
        free(local_ip);
    } else {
        strcpy(g_local_ip, "127.0.0.1");
    }
    
    g_p2p_socket = create_udp_socket(P2P_PORT);
    if (g_p2p_socket < 0) {
        return -1;
    }
    g_p2p_port = P2P_PORT;
    
    g_nat_type = p2p_detect_nat_type();
    g_has_ipv6 = p2p_has_ipv6();
    g_has_upnp = p2p_has_upnp();
    
    PLOG("NAT type: %d, IPv6: %d, UPnP: %d", g_nat_type, g_has_ipv6, g_has_upnp);
    PLOG("Local IP: %s, Port: %d", g_local_ip, g_p2p_port);
    
    g_initialized = true;
    
    g_listener_running = true;
    pthread_create(&g_listener_thread, NULL, listener_thread, NULL);
    
    g_keepalive_running = true;
    pthread_create(&g_keepalive_thread, NULL, keepalive_thread, NULL);
    
    PLOG("P2P initialized successfully");
    return 0;
}

void p2p_cleanup(void) {
    if (!g_initialized) return;
    
    PLOG("Cleaning up P2P manager");
    
    g_listener_running = false;
    if (g_listener_thread) {
        pthread_join(g_listener_thread, NULL);
        g_listener_thread = 0;
    }
    
    g_keepalive_running = false;
    if (g_keepalive_thread) {
        pthread_join(g_keepalive_thread, NULL);
        g_keepalive_thread = 0;
    }
    
    pthread_mutex_lock(&g_p2p_mutex);
    
    for (int i = 0; i < g_peer_count; i++) {
        if (g_peers[i].udp_socket >= 0) {
            close(g_peers[i].udp_socket);
            g_peers[i].udp_socket = -1;
        }
    }
    g_peer_count = 0;
    
    pthread_mutex_unlock(&g_p2p_mutex);
    
    if (g_p2p_socket >= 0) {
        close(g_p2p_socket);
        g_p2p_socket = -1;
    }
    
    g_initialized = false;
    PLOG("P2P cleaned up");
}

int p2p_connect(const char* peer_id) {
    if (!g_initialized) {
        PLOG("P2P not initialized");
        return -1;
    }
    
    char norm_id[64];
    normalize_id(peer_id, norm_id, sizeof(norm_id));
    
    PLOG("Connecting to peer %s", norm_id);
    
    P2PPeer* peer = find_peer(norm_id);
    if (peer && peer->state >= P2P_STATE_HANDSHAKE) {
        PLOG("Already connecting to %s", norm_id);
        return 0;
    }
    
    char ip[INET_ADDRSTRLEN];
    int port;
    
    DHTNode* dht = dht_node_create();
    if (!dht) {
        PLOG("Failed to create DHT node");
        return -1;
    }
    
    if (dht_node_start(dht, 33446) < 0) {
        dht_node_destroy(dht);
        PLOG("Failed to start DHT");
        return -1;
    }
    
    int found = dht_node_lookup(dht, norm_id, 10, ip, &port);
    dht_node_stop(dht);
    dht_node_destroy(dht);
    
    if (!found) {
        PLOG("Peer %s not found in DHT", norm_id);
        return -1;
    }
    
    PLOG("Peer %s at %s:%d", norm_id, ip, port);
    
    peer = add_peer(norm_id);
    if (!peer) {
        PLOG("Failed to add peer");
        return -1;
    }
    
    strcpy(peer->ip, ip);
    peer->port = port;
    peer->state = P2P_STATE_CONNECTING;
    peer->is_initiator = 1;
    peer->last_activity = time(NULL);
    
    memset(&peer->addr, 0, sizeof(peer->addr));
    peer->addr.sin_family = AF_INET;
    peer->addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &peer->addr.sin_addr);
    
    peer->udp_socket = create_udp_socket(0);
    if (peer->udp_socket < 0) {
        PLOG("Failed to create peer socket");
        peer->state = P2P_STATE_DISCONNECTED;
        return -1;
    }
    
    PLOG("Starting UDP hole punch to %s:%d", ip, port);
    
    int punch_result = p2p_hole_punch(ip, port, NAT_UNKNOWN);
    if (punch_result < 0) {
        PLOG("Hole punch failed for %s", norm_id);
        close(peer->udp_socket);
        peer->udp_socket = -1;
        peer->state = P2P_STATE_DISCONNECTED;
        return -1;
    }
    
    if (send_handshake(peer) < 0) {
        PLOG("Handshake failed for %s", norm_id);
        close(peer->udp_socket);
        peer->udp_socket = -1;
        peer->state = P2P_STATE_DISCONNECTED;
        return -1;
    }
    
    peer->state = P2P_STATE_HANDSHAKE;
    PLOG("Handshake sent to %s", norm_id);
    
    return 0;
}

int p2p_accept(const char* peer_id) {
    char norm_id[64];
    normalize_id(peer_id, norm_id, sizeof(norm_id));
    
    PLOG("Accepting connection from %s", norm_id);
    
    P2PPeer* peer = find_peer(norm_id);
    if (!peer) {
        PLOG("Peer %s not found", norm_id);
        return -1;
    }
    
    if (peer->state != P2P_STATE_HANDSHAKE) {
        PLOG("Peer %s not in handshake state", norm_id);
        return -1;
    }
    
    if (establish_secure_channel(peer) < 0) {
        PLOG("Failed to establish secure channel for %s", norm_id);
        return -1;
    }
    
    peer->state = P2P_STATE_ESTABLISHED;
    peer->is_secure = 1;
    peer->last_activity = time(NULL);
    
    state_update_peer(norm_id, PEER_FRIEND);
    
    Event event = event_create(EVENT_ACCEPT_CONFIRM, norm_id);
    event_queue_push(&event);
    
    PLOG("Connection accepted for %s", norm_id);
    return 0;
}

int p2p_disconnect(const char* peer_id) {
    char norm_id[64];
    normalize_id(peer_id, norm_id, sizeof(norm_id));
    
    PLOG("Disconnecting from %s", norm_id);
    
    P2PPeer* peer = find_peer(norm_id);
    if (!peer) {
        return -1;
    }
    
    if (peer->udp_socket >= 0) {
        uint8_t close_msg[1] = {0};
        send_message(peer, P2P_MSG_TYPE_CLOSE, close_msg, 1);
        close(peer->udp_socket);
        peer->udp_socket = -1;
    }
    
    peer->state = P2P_STATE_DISCONNECTED;
    peer->is_secure = 0;
    peer->last_activity = time(NULL);
    
    state_set_online(norm_id, 0);
    
    Event event = event_create(EVENT_PEER_OFFLINE, norm_id);
    event_queue_push(&event);
    
    PLOG("Disconnected from %s", norm_id);
    return 0;
}

int send_message(P2PPeer* peer, uint8_t type, const uint8_t* payload, size_t payload_len) {
    if (!peer || peer->udp_socket < 0) {
        return -1;
    }
    
    if (peer->state != P2P_STATE_ESTABLISHED && 
        type != P2P_MSG_TYPE_HANDSHAKE && 
        type != P2P_MSG_TYPE_HANDSHAKE_RESPONSE) {
        return -1;
    }
    
    size_t msg_size = sizeof(P2PMessage) + payload_len;
    uint8_t* buffer = (uint8_t*)malloc(msg_size);
    if (!buffer) {
        return -1;
    }
    
    P2PMessage* msg = (P2PMessage*)buffer;
    msg->magic = P2P_MAGIC;
    msg->version = P2P_PROTOCOL_VERSION;
    msg->type = type;
    msg->sequence = (uint32_t)time(NULL);
    msg->timestamp = (uint32_t)time(NULL);
    msg->payload_len = (uint32_t)payload_len;
    
    if (payload && payload_len > 0) {
        memcpy(msg->payload, payload, payload_len);
    }
    
    struct sockaddr_in addr;
    memcpy(&addr, &peer->addr, sizeof(addr));
    
    ssize_t sent = sendto(peer->udp_socket, buffer, msg_size, 0,
                          (struct sockaddr*)&addr, sizeof(addr));
    
    free(buffer);
    
    if (sent < 0) {
        PLOG("Failed to send message to %s: %s", peer->id, strerror(errno));
        return -1;
    }
    
    peer->last_activity = time(NULL);
    return 0;
}

int send_handshake(P2PPeer* peer) {
    OrcaIdentity identity;
    if (orca_identity_load(&identity, NULL) < 0) {
        PLOG("Failed to load identity for handshake");
        return -1;
    }
    
    char handshake_data[4096];
    snprintf(handshake_data, sizeof(handshake_data), 
             "%s|%s|%s|%ld",
             identity.id, identity.name, identity.public_key, 
             (long)time(NULL));
    
    uint8_t payload[4096];
    size_t payload_len = 0;
    
    memcpy(payload + payload_len, identity.id, strlen(identity.id));
    payload_len += strlen(identity.id);
    payload[payload_len++] = '|';
    
    memcpy(payload + payload_len, identity.public_key, strlen(identity.public_key));
    payload_len += strlen(identity.public_key);
    payload[payload_len++] = '|';
    
    char* signature = NULL;
    if (orca_rsa_sign_string(handshake_data, identity.private_key_encrypted, &signature) < 0) {
        PLOG("Failed to sign handshake");
        return -1;
    }
    
    memcpy(payload + payload_len, signature, strlen(signature));
    payload_len += strlen(signature);
    free(signature);
    
    return send_message(peer, P2P_MSG_TYPE_HANDSHAKE, payload, payload_len);
}

int generate_session_keys(P2PPeer* peer) {
    OrcaIdentity identity;
    if (orca_identity_load(&identity, NULL) < 0) {
        PLOG("Failed to load identity for key generation");
        return -1;
    }
    
    unsigned char ecdh_priv[32];
    unsigned char ecdh_pub[32];
    
    if (orca_x25519_generate_keypair(ecdh_pub, ecdh_priv) < 0) {
        PLOG("Failed to generate ECDH keypair");
        return -1;
    }
    
    unsigned char peer_pub[32];
    if (orca_x25519_hex_to_public_key(peer->public_key, peer_pub) < 0) {
        PLOG("Failed to parse peer public key");
        return -1;
    }
    
    unsigned char shared_secret[32];
    if (orca_x25519_compute_shared_secret(ecdh_priv, peer_pub, shared_secret) < 0) {
        PLOG("Failed to compute shared secret");
        return -1;
    }
    
    unsigned char salt[16];
    orca_random_bytes(salt, 16);
    
    if (orca_aes_gcm_derive_key_from_shared_secret(shared_secret, salt, 16,
                                                    (const unsigned char*)"orcashi-p2p", 10,
                                                    peer->aes_key) < 0) {
        PLOG("Failed to derive AES key");
        return -1;
    }
    
    memcpy(peer->shared_secret, shared_secret, 32);
    
    zeroize(ecdh_priv, 32);
    zeroize(shared_secret, 32);
    
    PLOG("Session keys generated for %s", peer->id);
    return 0;
}

int establish_secure_channel(P2PPeer* peer) {
    if (generate_session_keys(peer) < 0) {
        return -1;
    }
    
    uint8_t confirm[1] = {1};
    return send_message(peer, P2P_MSG_TYPE_HANDSHAKE_RESPONSE, confirm, 1);
}

int p2p_send(const char* peer_id, const char* message) {
    if (!peer_id || !message) return -1;
    
    char norm_id[64];
    normalize_id(peer_id, norm_id, sizeof(norm_id));
    
    P2PPeer* peer = find_peer(norm_id);
    if (!peer) {
        PLOG("Peer %s not found", norm_id);
        return -1;
    }
    
    if (peer->state != P2P_STATE_ESTABLISHED) {
        PLOG("Peer %s not connected", norm_id);
        return -1;
    }
    
    if (peer->is_secure) {
        return p2p_send_secure(peer_id, (const unsigned char*)message, strlen(message));
    }
    
    return send_message(peer, P2P_MSG_TYPE_DATA, (const uint8_t*)message, strlen(message));
}

int p2p_send_secure(const char* peer_id, const unsigned char* data, size_t len) {
    if (!peer_id || !data || len == 0) return -1;
    
    char norm_id[64];
    normalize_id(peer_id, norm_id, sizeof(norm_id));
    
    P2PPeer* peer = find_peer(norm_id);
    if (!peer || peer->state != P2P_STATE_ESTABLISHED) {
        return -1;
    }
    
    if (!peer->is_secure) {
        return -1;
    }
    
    unsigned char nonce[12];
    orca_random_bytes(nonce, 12);
    
    unsigned char tag[16];
    unsigned char* ciphertext;
    size_t ciphertext_len;
    
    if (orca_aes_gcm_encrypt(data, len, peer->aes_key, nonce, tag, 
                              &ciphertext, &ciphertext_len) < 0) {
        PLOG("Failed to encrypt message for %s", norm_id);
        return -1;
    }
    
    size_t total_len = 12 + 16 + ciphertext_len;
    uint8_t* payload = (uint8_t*)malloc(total_len);
    if (!payload) {
        free(ciphertext);
        return -1;
    }
    
    memcpy(payload, nonce, 12);
    memcpy(payload + 12, tag, 16);
    memcpy(payload + 12 + 16, ciphertext, ciphertext_len);
    
    free(ciphertext);
    
    int result = send_message(peer, P2P_MSG_TYPE_DATA, payload, total_len);
    free(payload);
    
    return result;
}

int p2p_recv(const char* peer_id, char* message, int max_len) {
    if (!peer_id || !message || max_len <= 0) return -1;
    
    char norm_id[64];
    normalize_id(peer_id, norm_id, sizeof(norm_id));
    
    P2PPeer* peer = find_peer(norm_id);
    if (!peer || peer->state != P2P_STATE_ESTABLISHED) {
        return -1;
    }
    
    return 0;
}

int handle_handshake(P2PPeer* peer, const P2PMessage* msg) {
    PLOG("Handshake received from %s", peer->id);
    
    char* payload = (char*)msg->payload;
    char* id = payload;
    char* pubkey = strchr(payload, '|');
    if (!pubkey) {
        PLOG("Invalid handshake payload");
        return -1;
    }
    *pubkey = '\0';
    pubkey++;
    
    char* signature = strchr(pubkey, '|');
    if (!signature) {
        PLOG("Invalid handshake payload (no signature)");
        return -1;
    }
    *signature = '\0';
    signature++;
    
    OrcaIdentity identity;
    if (orca_identity_load(&identity, NULL) < 0) {
        PLOG("Failed to load identity");
        return -1;
    }
    
    char data_to_verify[4096];
    snprintf(data_to_verify, sizeof(data_to_verify), 
             "%s|%s|%s|%ld",
             id, identity.name, identity.public_key,
             (long)time(NULL));
    
    if (!orca_rsa_verify_string(data_to_verify, signature, pubkey)) {
        PLOG("Handshake signature verification failed");
        return -1;
    }
    
    strcpy(peer->public_key, pubkey);
    peer->is_secure = 1;
    
    if (establish_secure_channel(peer) < 0) {
        PLOG("Failed to establish secure channel");
        return -1;
    }
    
    peer->state = P2P_STATE_ESTABLISHED;
    peer->last_activity = time(NULL);
    
    state_update_peer(peer->id, PEER_FRIEND);
    state_set_online(peer->id, 1);
    state_set_ip(peer->id, peer->ip);
    state_set_port(peer->id, peer->port);
    
    Event event = event_create(EVENT_ACCEPT_CONFIRM, peer->id);
    event_queue_push(&event);
    
    PLOG("Handshake completed for %s", peer->id);
    return 0;
}

int handle_data(P2PPeer* peer, const P2PMessage* msg) {
    if (peer->is_secure && msg->payload_len > 28) {
        unsigned char nonce[12];
        unsigned char tag[16];
        unsigned char* ciphertext = (unsigned char*)msg->payload + 28;
        size_t ciphertext_len = msg->payload_len - 28;
        
        memcpy(nonce, msg->payload, 12);
        memcpy(tag, msg->payload + 12, 16);
        
        unsigned char* plaintext;
        size_t plaintext_len;
        
        if (orca_aes_gcm_decrypt(ciphertext, ciphertext_len,
                                  peer->aes_key, nonce, tag,
                                  &plaintext, &plaintext_len) < 0) {
            PLOG("Failed to decrypt message from %s", peer->id);
            return -1;
        }
        
        plaintext[plaintext_len] = '\0';
        
        Event event = event_create(EVENT_MESSAGE_RECEIVED, peer->id);
        strcpy(event.from_id, peer->id);
        strcpy(event.message, (char*)plaintext);
        event_queue_push(&event);
        
        state_add_message(peer->id, (char*)plaintext);
        
        free(plaintext);
    } else {
        char* message = (char*)msg->payload;
        message[msg->payload_len] = '\0';
        
        Event event = event_create(EVENT_MESSAGE_RECEIVED, peer->id);
        strcpy(event.from_id, peer->id);
        strcpy(event.message, message);
        event_queue_push(&event);
        
        state_add_message(peer->id, message);
    }
    
    peer->last_activity = time(NULL);
    return 0;
}

int handle_add_request(P2PPeer* peer, const P2PMessage* msg) {
    char* from_id = (char*)msg->payload;
    from_id[msg->payload_len] = '\0';
    
    PLOG("Add request received from %s", from_id);
    
    state_update_peer(from_id, PEER_REQUEST_RECEIVED);
    state_set_ip(from_id, peer->ip);
    state_set_port(from_id, peer->port);
    
    Event event = event_create(EVENT_ADD_REQUEST, from_id);
    strcpy(event.from_id, from_id);
    strcpy(event.ip, peer->ip);
    event.port = peer->port;
    event_queue_push(&event);
    
    return 0;
}

int handle_accept_confirm(P2PPeer* peer, const P2PMessage* msg) {
    char* from_id = (char*)msg->payload;
    from_id[msg->payload_len] = '\0';
    
    PLOG("Accept confirm received from %s", from_id);
    
    state_update_peer(from_id, PEER_FRIEND);
    state_set_online(from_id, 1);
    state_set_ip(from_id, peer->ip);
    state_set_port(from_id, peer->port);
    
    int ghost_count = state_deliver_ghost_messages(from_id);
    if (ghost_count > 0) {
        PLOG("Delivered %d ghost messages to %s", ghost_count, from_id);
    }
    
    Event event = event_create(EVENT_ACCEPT_CONFIRM, from_id);
    event_queue_push(&event);
    
    return 0;
}

int handle_reject_confirm(P2PPeer* peer, const P2PMessage* msg) {
    (void)peer;
    char* from_id = (char*)msg->payload;
    from_id[msg->payload_len] = '\0';
    
    PLOG("Reject confirm received from %s", from_id);
    
    state_remove_peer(from_id);
    
    Event event = event_create(EVENT_REJECT_CONFIRM, from_id);
    event_queue_push(&event);
    
    return 0;
}

int process_message(P2PPeer* peer, const P2PMessage* msg, size_t msg_len) {
    if (!peer || !msg || msg_len < sizeof(P2PMessage)) {
        return -1;
    }
    
    if (msg->magic != P2P_MAGIC) {
        PLOG("Invalid magic from %s", peer->id);
        return -1;
    }
    
    if (msg->version != P2P_PROTOCOL_VERSION) {
        PLOG("Unsupported version from %s", peer->id);
        return -1;
    }
    
    switch (msg->type) {
        case P2P_MSG_TYPE_HANDSHAKE:
            return handle_handshake(peer, msg);
            
        case P2P_MSG_TYPE_HANDSHAKE_RESPONSE:
            PLOG("Handshake response from %s", peer->id);
            peer->state = P2P_STATE_ESTABLISHED;
            peer->is_secure = 1;
            peer->last_activity = time(NULL);
            return 0;
            
        case P2P_MSG_TYPE_DATA:
            return handle_data(peer, msg);
            
        case P2P_MSG_TYPE_KEEPALIVE:
            peer->last_activity = time(NULL);
            return 0;
            
        case P2P_MSG_TYPE_CLOSE:
            PLOG("Close received from %s", peer->id);
            peer->state = P2P_STATE_DISCONNECTED;
            return 0;
            
        case P2P_MSG_TYPE_ADD_REQUEST:
            return handle_add_request(peer, msg);
            
        case P2P_MSG_TYPE_ACCEPT_CONFIRM:
            return handle_accept_confirm(peer, msg);
            
        case P2P_MSG_TYPE_REJECT_CONFIRM:
            return handle_reject_confirm(peer, msg);
            
        default:
            PLOG("Unknown message type from %s: %d", peer->id, msg->type);
            return -1;
    }
}

void* listener_thread(void* arg) {
    (void)arg;
    
    PLOG("Listener thread started");
    
    uint8_t buffer[4096];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    fd_set fds;
    struct timeval tv;
    
    while (g_listener_running) {
        FD_ZERO(&fds);
        FD_SET(g_p2p_socket, &fds);
        
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ret = select(g_p2p_socket + 1, &fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (g_listener_running) {
                PLOG("select error: %s", strerror(errno));
            }
            break;
        }
        
        if (ret == 0) continue;
        
        int n = recvfrom(g_p2p_socket, buffer, sizeof(buffer), 0,
                         (struct sockaddr*)&from, &from_len);
        
        if (n <= 0) {
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                PLOG("recvfrom error: %s", strerror(errno));
            }
            continue;
        }
        
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
        int port = ntohs(from.sin_port);
        
        if (n < (int)sizeof(P2PMessage)) {
            PLOG("Received truncated message from %s:%d", ip, port);
            continue;
        }
        
        P2PMessage* msg = (P2PMessage*)buffer;
        
        if (msg->magic != P2P_MAGIC) {
            PLOG("Invalid magic from %s:%d", ip, port);
            continue;
        }
        
        pthread_mutex_lock(&g_p2p_mutex);
        
        int found = 0;
        for (int i = 0; i < g_peer_count; i++) {
            if (g_peers[i].port == port && 
                strcmp(g_peers[i].ip, ip) == 0) {
                found = 1;
                process_message(&g_peers[i], msg, n);
                break;
            }
        }
        
        if (!found && msg->type == P2P_MSG_TYPE_HANDSHAKE) {
            char* payload = (char*)msg->payload;
            char* id = payload;
            char* pubkey = strchr(payload, '|');
            if (pubkey) {
                *pubkey = '\0';
                pubkey++;
                
                P2PPeer* peer = add_peer(id);
                if (peer) {
                    strcpy(peer->ip, ip);
                    peer->port = port;
                    peer->state = P2P_STATE_HANDSHAKE;
                    peer->udp_socket = -1;
                    peer->is_initiator = 0;
                    peer->last_activity = time(NULL);
                    
                    memset(&peer->addr, 0, sizeof(peer->addr));
                    peer->addr.sin_family = AF_INET;
                    peer->addr.sin_port = htons(port);
                    inet_pton(AF_INET, ip, &peer->addr.sin_addr);
                    
                    process_message(peer, msg, n);
                }
            }
        }
        
        pthread_mutex_unlock(&g_p2p_mutex);
    }
    
    PLOG("Listener thread stopped");
    return NULL;
}

void* keepalive_thread(void* arg) {
    (void)arg;
    
    PLOG("Keepalive thread started");
    
    while (g_keepalive_running) {
        sleep(P2P_KEEPALIVE_INTERVAL);
        
        if (!g_keepalive_running) break;
        
        pthread_mutex_lock(&g_p2p_mutex);
        
        time_t now = time(NULL);
        
        for (int i = 0; i < g_peer_count; i++) {
            P2PPeer* peer = &g_peers[i];
            
            if (peer->state == P2P_STATE_ESTABLISHED) {
                if (now - peer->last_activity > P2P_KEEPALIVE_INTERVAL * 2) {
                    uint8_t keepalive[1] = {0};
                    send_message(peer, P2P_MSG_TYPE_KEEPALIVE, keepalive, 1);
                }
                
                if (now - peer->last_activity > P2P_KEEPALIVE_INTERVAL * 5) {
                    PLOG("Peer %s timed out", peer->id);
                    peer->state = P2P_STATE_DISCONNECTED;
                    peer->is_secure = 0;
                    state_set_online(peer->id, 0);
                    
                    Event event = event_create(EVENT_PEER_OFFLINE, peer->id);
                    event_queue_push(&event);
                }
            }
        }
        
        pthread_mutex_unlock(&g_p2p_mutex);
    }
    
    PLOG("Keepalive thread stopped");
    return NULL;
}

NATType p2p_detect_nat_type(void) {
    PLOG("Detecting NAT type...");
    
    NATType type = nat_classify_via_dht(NULL, NULL);
    
    PLOG("NAT type detected: %d", type);
    return type;
}

bool p2p_has_ipv6(void) {
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) return 0;
    
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(53);
    inet_pton(AF_INET6, "2001:4860:4860::8888", &addr.sin6_addr);
    
    int has = (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0);
    close(sock);
    
    return has;
}

bool p2p_has_upnp(void) {
    return upnp_detect();
}

int p2p_hole_punch(const char* ip, int port, NATType peer_nat) {
    if (!ip || port <= 0) return -1;
    
    PLOG("Hole punching to %s:%d", ip, port);
    
    int result = punch_multi_strategy(ip, port, g_nat_type, peer_nat);
    
    if (result == 0) {
        PLOG("Hole punch successful to %s:%d", ip, port);
    } else {
        PLOG("Hole punch failed to %s:%d", ip, port);
    }
    
    return result;
}

int p2p_punch_listen(char* ip_out, int* port_out) {
    if (!ip_out || !port_out) return -1;
    
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    char buffer[256];
    
    int n = recvfrom(g_p2p_socket, buffer, sizeof(buffer) - 1, 0,
                     (struct sockaddr*)&from, &from_len);
    
    if (n < 0) return -1;
    
    buffer[n] = '\0';
    
    if (strcmp(buffer, "ORCA_PUNCH") == 0 ||
        strcmp(buffer, "ORCA_PUNCH_RESPONSE") == 0) {
        inet_ntop(AF_INET, &from.sin_addr, ip_out, INET_ADDRSTRLEN);
        *port_out = ntohs(from.sin_port);
        return 0;
    }
    
    return -1;
}

int p2p_get_peer_capability(const char* peer_id, PeerCapability* cap) {
    if (!peer_id || !cap) return -1;
    
    memset(cap, 0, sizeof(PeerCapability));
    strcpy(cap->id, peer_id);
    cap->nat_type = NAT_UNKNOWN;
    cap->has_ipv6 = 0;
    cap->has_upnp = 0;
    
    DHTNode* dht = dht_node_create();
    if (!dht) return -1;
    
    if (dht_node_start(dht, 33446) < 0) {
        dht_node_destroy(dht);
        return -1;
    }
    
    char ip[INET_ADDRSTRLEN];
    int port;
    int found = dht_node_lookup(dht, peer_id, 5, ip, &port);
    
    dht_node_stop(dht);
    dht_node_destroy(dht);
    
    if (found) {
        strcpy(cap->ip, ip);
        cap->port = port;
    }
    
    return found ? 0 : -1;
}

int p2p_exchange_capabilities(const char* peer_id, PeerCapability* remote) {
    if (!peer_id || !remote) return -1;
    
    return p2p_get_peer_capability(peer_id, remote);
}

bool p2p_is_connected(const char* peer_id) {
    P2PPeer* peer = find_peer(peer_id);
    return peer && peer->state == P2P_STATE_ESTABLISHED;
}

bool p2p_is_secure(const char* peer_id) {
    P2PPeer* peer = find_peer(peer_id);
    return peer && peer->is_secure;
}

P2PState p2p_get_state(const char* peer_id) {
    P2PPeer* peer = find_peer(peer_id);
    return peer ? peer->state : P2P_STATE_DISCONNECTED;
}

NATType p2p_get_nat_type(void) {
    return g_nat_type;
}

void p2p_debug_print(void) {
    pthread_mutex_lock(&g_p2p_mutex);
    
    printf("\n=== P2P MANAGER DEBUG ===\n");
    printf("Socket: %d\n", g_p2p_socket);
    printf("Port: %d\n", g_p2p_port);
    printf("Local IP: %s\n", g_local_ip);
    printf("NAT Type: %d\n", g_nat_type);
    printf("IPv6: %s\n", g_has_ipv6 ? "YES" : "NO");
    printf("UPnP: %s\n", g_has_upnp ? "YES" : "NO");
    printf("Peers: %d\n", g_peer_count);
    
    for (int i = 0; i < g_peer_count; i++) {
        P2PPeer* p = &g_peers[i];
        printf("  [%d] %s | state=%d | ip=%s:%d | secure=%d | socket=%d\n",
               i, p->id, p->state, p->ip, p->port, p->is_secure, p->udp_socket);
    }
    
    printf("==========================\n");
    
    pthread_mutex_unlock(&g_p2p_mutex);
}
