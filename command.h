#ifndef COMMANDS_H
#define COMMANDS_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ============================================================================
 * COMMAND TYPES
 * ============================================================================ */

typedef enum {
    CMD_UNKNOWN = 0,
    CMD_REGISTER,
    CMD_IDENTITY,
    CMD_LISTEN,
    CMD_SEARCH,
    CMD_ADD,
    CMD_ACCEPT,
    CMD_REJECT,
    CMD_PEERS,
    CMD_CHAT,
    CMD_GHOST,
    CMD_STATUS,
    CMD_STOP,
    CMD_HELP
} CommandType;

/* ============================================================================
 * COMMAND RESULT
 * ============================================================================ */

typedef struct {
    int exit_code;
    char message[512];
    bool async;  /* True if command runs in background */
} CommandResult;

/* ============================================================================
 * COMMAND HANDLER FUNCTIONS
 * ============================================================================ */

/* Main command dispatcher */
int command_dispatch(int argc, char* argv[]);

/* Individual command handlers */
int cmd_register(int argc, char* argv[]);
int cmd_identity(int argc, char* argv[]);
int cmd_listen(int argc, char* argv[]);
int cmd_search(int argc, char* argv[]);
int cmd_add(int argc, char* argv[]);
int cmd_accept(int argc, char* argv[]);
int cmd_reject(int argc, char* argv[]);
int cmd_peers(int argc, char* argv[]);
int cmd_chat(int argc, char* argv[]);
int cmd_ghost(int argc, char* argv[]);
int cmd_status(int argc, char* argv[]);
int cmd_stop(int argc, char* argv[]);
int cmd_help(int argc, char* argv[]);

/* ============================================================================
 * COMMAND HELPERS
 * ============================================================================ */

/* Send command to background daemon */
int command_send_to_daemon(const char* cmd, char* response, size_t response_size);

/* Check if daemon is running */
bool command_daemon_is_running(void);

/* Get daemon PID */
int command_get_daemon_pid(void);

/* ============================================================================
 * COMMAND PARSING
 * ============================================================================ */

CommandType command_parse_type(const char* cmd);
const char* command_get_name(CommandType type);
void command_show_help(void);

#endif /* COMMANDS_H */
