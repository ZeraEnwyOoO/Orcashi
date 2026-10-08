# Makefile for Orcashi P2P project
# Version: 16.1.1

CC       := gcc
TARGET   := orcashi
BUILD_DIR := build
SRC_DIR  := .

# Compiler flags
CFLAGS   := -Wall -Wextra -Wpedantic -std=c11 -O2 -g \
            -D_GNU_SOURCE -DORCA_VERSION=\"16.1.1\"

# Linker flags - add libraries as needed
LDFLAGS  :=
LDLIBS   := -lpthread -lm

# Optional: uncomment if you use OpenSSL for crypto
# CFLAGS  += $(shell pkg-config --cflags openssl)
# LDLIBS  += $(shell pkg-config --libs openssl)

# Source files
SRCS := \
	aes_gcm.c \
	bootstrap.c \
	commands.c \
	daemon.c \
	dht.c \
	dht_impl.c \
	dht_node.c \
	ecdh.c \
	event_loop.c \
	friend_relay.c \
	logger.c \
	main.c \
	mixed_id.c \
	nat_classifier.c \
	orca_crypto.c \
	orca_identity.c \
	orcashi.c \
	p2p_manager.c \
	parallel_runner.c \
	port_prediction.c \
	punch.c \
	simultaneous_open.c \
	state_manager.c \
	strategy_selector.c \
	ttl_punch.c \
	turn_client.c \
	upnp_client.c

# Header files (for dependency tracking)
HDRS := $(wildcard *.h)

# Object files
OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SRCS))

# Default target
.PHONY: all
all: $(BUILD_DIR)/$(TARGET)

# Link
$(BUILD_DIR)/$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

# Compile
$(BUILD_DIR)/%.o: %.c $(HDRS) | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Run
.PHONY: run
run: all
	./$(BUILD_DIR)/$(TARGET)

# Clean
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

# Rebuild
.PHONY: rebuild
rebuild: clean all

# Debug build
.PHONY: debug
debug: CFLAGS += -DDEBUG -O0 -g3 -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefined
debug: rebuild

# Release build
.PHONY: release
release: CFLAGS := -Wall -Wextra -std=c11 -O3 -DNDEBUG -DORCA_VERSION=\"16.1.1\"
release: rebuild

# Print variables (debugging)
.PHONY: info
info:
	@echo "CC:      $(CC)"
	@echo "TARGET:  $(TARGET)"
	@echo "SRCS:    $(words $(SRCS)) files"
	@echo "OBJS:    $(OBJS)"
	@echo "CFLAGS:  $(CFLAGS)"
	@echo "LDLIBS:  $(LDLIBS)"

# Auto-generate dependencies
-include $(OBJS:.o=.d)
CFLAGS += -MMD -MP
