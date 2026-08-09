 # Makefile for ORCASHI with DHT
CC = gcc
CFLAGS = -std=c99 -Wall -O2 -D_GNU_SOURCE -pthread
LDFLAGS = -lpthread -lssl -lcrypto
TARGET = orcashi

SRCS = main.c orcashi.c plug.c discovery.c registry.c request.c \
       peer_cache.c endpoint.c dht.c dht_impl.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo "✅ ORCASHI with DHT compiled successfully!"
	@echo "Run: ./$(TARGET)"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
	@echo "🧹 Cleaned!"

run: $(TARGET)
	./$(TARGET)

debug: CFLAGS += -g -DDEBUG
debug: clean $(TARGET)

.PHONY: all clean run debug
