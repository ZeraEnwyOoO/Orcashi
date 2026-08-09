 // orcashi.c - ORCASHI Main Implementation in C
#include "orcashi.h"
#include <sys/stat.h>
#include <sys/types.h>

#define ORCASHI_HOME "/tmp/.orcashi/"
#define ID_FILE ORCASHI_HOME "id"
#define MAX_ID_LEN 64
#define MAX_MSG_LEN 4096

static char* orcashi_get_peer_id_from_ip(const char* ip);
static void* chat_loop_thread(void* arg);

ORCASHI* orcashi_create(void) {
    ORCASHI* orcashi = (ORCASHI*)calloc(1, sizeof(ORCASHI));
    if (!orcashi) return NULL;
    
    orcashi->plug = plug_create();
    if (!orcashi->plug) {
        free(orcashi);
        return NULL;
    }
    
    // Create home directory
    mkdir(ORCASHI_HOME, 0700);
    
    // Generate ID
    char* id = orcashi_generate_id();
    strcpy(orcashi->my_id, id);
    free(id);
    
    // Get local IP
    char* ip = orcashi_get_local_ip();
    strcpy(orcashi->local_ip, ip);
    free(ip);
    
    orcashi->connected = false;
    orcashi->running = false;
    
    return orcashi;
}

void orcashi_destroy(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    orcashi_disconnect(orcashi);
    
    if (orcashi->plug) {
        plug_destroy(orcashi->plug);
        orcashi->plug = NULL;
    }
    
    free(orcashi);
}

bool orcashi_init(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    printf("[ORCA] Initialized with ID: %s\n", orcashi->my_id);
    printf("[ORCA] Local IP: %s\n", orcashi->local_ip);
    
    return true;
}

bool orcashi_create_room(ORCASHI* orcashi, int port) {
    if (!orcashi) return false;
    
    printf("\n%s\n", "================================================");
    printf("ORCASHI - CREATE ROOM\n");
    printf("%s\n", "================================================");
    
    if (plug_create_server(orcashi->plug, port)) {
        orcashi->connected = true;
        orcashi->running = true;
        
        // Get peer ID
        const char* peer_ip = plug_get_peer_ip(orcashi->plug);
        if (peer_ip) {
            char* peer_id = orcashi_get_peer_id_from_ip(peer_ip);
            strcpy(orcashi->peer_id, peer_id);
            free(peer_id);
        }
        
        orcashi_show_banner(orcashi);
        return true;
    }
    
    return false;
}

bool orcashi_join_room(ORCASHI* orcashi, const char* ip, int port) {
    if (!orcashi) return false;
    
    printf("\n%s\n", "================================================");
    printf("ORCASHI - JOIN ROOM\n");
    printf("%s\n", "================================================");
    
    if (plug_connect_client(orcashi->plug, ip, port)) {
        orcashi->connected = true;
        orcashi->running = true;
        
        char* peer_id = orcashi_get_peer_id_from_ip(ip);
        strcpy(orcashi->peer_id, peer_id);
        free(peer_id);
        
        orcashi_show_banner(orcashi);
        return true;
    }
    
    return false;
}

bool orcashi_send_message(ORCASHI* orcashi, const char* msg) {
    if (!orcashi || !orcashi->connected) return false;
    return plug_send_message(orcashi->plug, msg);
}

bool orcashi_receive_message(ORCASHI* orcashi, char* msg, int msg_size, int timeout_ms) {
    if (!orcashi || !orcashi->connected) return false;
    return plug_receive_message(orcashi->plug, msg, msg_size, timeout_ms);
}

bool orcashi_is_connected(ORCASHI* orcashi) {
    return orcashi && orcashi->connected && plug_is_connected(orcashi->plug);
}

void orcashi_disconnect(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    orcashi->connected = false;
    orcashi->running = false;
    
    if (orcashi->plug) {
        plug_close_connection(orcashi->plug);
    }
}

const char* orcashi_get_my_id(ORCASHI* orcashi) {
    return orcashi ? orcashi->my_id : NULL;
}

const char* orcashi_get_peer_id(ORCASHI* orcashi) {
    return orcashi ? orcashi->peer_id : NULL;
}

const char* orcashi_get_peer_ip(ORCASHI* orcashi) {
    return orcashi ? plug_get_peer_ip(orcashi->plug) : NULL;
}

bool orcashi_register_identity(ORCASHI* orcashi) {
    if (!orcashi) return false;
    
    printf("\n");
    printf("  +------------------------------------------+\n");
    printf("  |           ORCA Registration              |\n");
    printf("  +------------------------------------------+\n");
    printf("\n");
    
    printf("  Your ID: %s\n", orcashi->my_id);
    printf("  Your IP: %s\n", orcashi->local_ip);
    
    // Save ID to file
    FILE* f = fopen(ID_FILE, "w");
    if (f) {
        fprintf(f, "%s", orcashi->my_id);
        fclose(f);
    }
    
    printf("\n  [SUCCESS] Registered!\n");
    printf("  Your friends can connect using:\n");
    printf("    ./orcashi connect %s\n", orcashi->my_id);
    
    return true;
}

bool orcashi_connect_peer(ORCASHI* orcashi, const char* id) {
    if (!orcashi) return false;
    
    printf("\n  [ORCA] Looking for %s...\n", id);
    
    // For v1.0, we just use IP directly
    // In future versions, we'll use DHT
    
    printf("  [ORCA] Enter IP for %s: ", id);
    char ip[INET_ADDRSTRLEN];
    if (!fgets(ip, sizeof(ip), stdin)) {
        return false;
    }
    ip[strcspn(ip, "\n")] = '\0';
    
    return orcashi_join_room(orcashi, ip, 9000);
}

void orcashi_show_peers(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    printf("\n  Your Peers:\n");
    if (orcashi->connected) {
        printf("    %s - %s [ONLINE]\n", orcashi->peer_id, orcashi->local_ip);
    } else {
        printf("    No peers connected.\n");
    }
    printf("\n");
}

void orcashi_show_banner(ORCASHI* orcashi) {
    if (!orcashi) return;
    
    printf("\033[36m");
    printf("%s\n", "============================================================");
    printf("  ██████╗ ██████╗  ██████╗ █████╗ \n");
    printf(" ██╔═══██╗██╔══██╗██╔════╝██╔══██╗C\n");
    printf(" ██║   ██║██████╔╝██║     ███████╗H\n");
    printf(" ██║   ██║██╔══██╗██║     ██╔══██╗A\n");
    printf(" ╚██████╔╝██║  ██║╚██████╗██║  ██║T\n");
    printf("  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝\n");
    printf("            ORCASHI v1.0 - P2P Chat\n");
    printf("%s\n", "============================================================");
    printf("\033[0m");
    
    printf("Your ID: %s\n", orcashi->my_id);
    printf("Mode: TCP Plug (C Version)\n");
    printf("DHT: Not connected (v1.0)\n");
    printf("Type /help for commands\n");
    printf("%s\n", "============================================================");
    printf("\n");
}

void orcashi_show_help(void) {
    printf("\n%s\n", "================================================");
    printf("ORCASHI v1.0 - P2P Chat\n");
    printf("%s\n", "================================================");
    printf("Commands:\n");
    printf("  /help    - Show this help\n");
    printf("  /exit    - Disconnect\n");
    printf("  /status  - Show connection status\n");
    printf("\n");
}

char* orcashi_generate_id(void) {
    static char id[64];
    
    // Try to read from file
    FILE* f = fopen(ID_FILE, "r");
    if (f) {
        if (fgets(id, sizeof(id), f)) {
            id[strcspn(id, "\n")] = '\0';
            fclose(f);
            return strdup(id);
        }
        fclose(f);
    }
    
    // Generate new ID
    srand(time(NULL) ^ getpid());
    int num = (rand() % 999) + 1;
    snprintf(id, sizeof(id), "<%03d>", num);
    
    // Save to file
    f = fopen(ID_FILE, "w");
    if (f) {
        fprintf(f, "%s", id);
        fclose(f);
    }
    
    return strdup(id);
}

char* orcashi_get_local_ip(void) {
    static char ip[INET_ADDRSTRLEN];
    struct ifaddrs* ifaddr;
    
    if (getifaddrs(&ifaddr) == -1) {
        strcpy(ip, "127.0.0.1");
        return ip;
    }
    
    for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, "lo") == 0) continue;
        
        struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip, INET_ADDRSTRLEN);
        freeifaddrs(ifaddr);
        return strdup(ip);
    }
    
    freeifaddrs(ifaddr);
    strcpy(ip, "127.0.0.1");
    return strdup(ip);
}

static char* orcashi_get_peer_id_from_ip(const char* ip) {
    static char id[64];
    snprintf(id, sizeof(id), "%s", ip);
    return strdup(id);
}
