 // main.c - Orcashi v5 - Real P2P, Async UX
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "commands.h"
#include "daemon.h"
#include "state_manager.h"
#include "p2p_manager.h"
#include "mixed_id.h"
#include "orca_identity.h"
#include "orca_crypto.h"

#define VERSION "5.0.0"
#define ORCASHI_HOME "/tmp/.orcashi/"

static volatile int g_running = 1;

/* ============================================================================
 * SIGNAL HANDLER
 * ============================================================================ */

void signal_handler(int sig) {
    (void)sig;
    printf("\n[ORCA] Shutting down...\n");
    g_running = 0;
    
    if (daemon_is_running()) {
        daemon_stop();
    }
    
    exit(0);
}

/* ============================================================================
 * BANNER
 * ============================================================================ */

void show_banner(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                  ║\n");
    printf("║   ██████╗ ██████╗  ██████╗ █████╗ ███████╗██╗  ██╗██╗           ║\n");
    printf("║   ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║██║           ║\n");
    printf("║   ██████╔╝██████╔╝██║     ███████║███████╗███████║██║           ║\n");
    printf("║   ██╔══██╗██╔══██╗██║     ██╔══██║╚════██║██╔══██║██║           ║\n");
    printf("║   ██║  ██║██║  ██║╚██████╗██║  ██║███████║██║  ██║██║           ║\n");
    printf("║   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝           ║\n");
    printf("║                                                                  ║\n");
    printf("║   ORCASHI v%s — REAL P2P, ASYNC UX                              ║\n", VERSION);
    printf("║                                                                  ║\n");
    printf("║   \"DHT DISCOVERY → DIRECT UDP → NO RELAY SERVER\"               ║\n");
    printf("║                                                                  ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

/* ============================================================================
 * VERSION
 * ============================================================================ */

void show_version(void) {
    printf("Orcashi v%s\n", VERSION);
    printf("Real P2P, Async UX\n");
    printf("No relay server, no centralization\n");
}

/* ============================================================================
 * CHECK DEPENDENCIES
 * ============================================================================ */

static int check_dependencies(void) {
    /* Check if OpenSSL is available */
    /* Check if home directory is writable */
    if (access(ORCASHI_HOME, F_OK) != 0) {
        if (mkdir(ORCASHI_HOME, 0700) != 0) {
            fprintf(stderr, "[ERROR] Cannot create %s: %s\n", ORCASHI_HOME, strerror(errno));
            return -1;
        }
    }
    
    return 0;
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

int main(int argc, char* argv[]) {
    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    /* Initialize crypto */
    orca_init_crypto();
    orca_identity_storage_init();
    
    /* Check dependencies */
    if (check_dependencies() < 0) {
        return 1;
    }
    
    /* Create home directory */
    mkdir(ORCASHI_HOME, 0700);
    
    /* Show banner */
    if (argc < 2) {
        show_banner();
        command_show_help();
        return 0;
    }
    
    /* Check for version flag */
    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
        show_version();
        return 0;
    }
    
    /* Check for help flag */
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        command_show_help();
        return 0;
    }
    
    /* Initialize state manager (for commands that need it) */
    state_init();
    
    /* Dispatch command */
    int result = command_dispatch(argc, argv);
    
    /* Cleanup */
    state_save();
    orca_cleanup_crypto();
    
    return result;
}
