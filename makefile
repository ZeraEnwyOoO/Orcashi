 # ORCASHI Makefile
CC = gcc
CFLAGS = -Wall -O2 -std=gnu99 -pthread
LDFLAGS = -lpthread

TARGET = orcashi
SRCDIR = src
OBJDIR = obj

SOURCES = $(SRCDIR)/main.c \
          $(SRCDIR)/orcashi.c \
          $(SRCDIR)/plug.c \
          $(SRCDIR)/discovery.c \
          $(SRCDIR)/registry.c \
          $(SRCDIR)/request.c \
          $(SRCDIR)/peer_cache.c \
          $(SRCDIR)/endpoint.c \
          $(SRCDIR)/nat_punch.c \
          $(SRCDIR)/bootstrap.c \
          $(SRCDIR)/dht.c

OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR) $(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall
