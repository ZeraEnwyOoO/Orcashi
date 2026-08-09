 # Makefile for ORCASHI DHT
CXX = g++
CC = gcc
CXXFLAGS = -std=c++17 -Wall -O2 -pthread
CFLAGS = -std=c99 -Wall -O2 -pthread
LDFLAGS = -lssl -lcrypto -lpthread -lstdc++

# Target executable
TARGET = orcashi_dht

# Source files
C_SOURCES = dht.c dht_impl.c
CPP_SOURCES = dht_wrapper.cpp main.cpp

# Object files
C_OBJECTS = $(C_SOURCES:.c=.o)
CPP_OBJECTS = $(CPP_SOURCES:.cpp=.o)
OBJECTS = $(C_OBJECTS) $(CPP_OBJECTS)

# Default target
all: $(TARGET)

# Link
$(TARGET): $(OBJECTS)
	$(CXX) -o $@ $^ $(LDFLAGS)

# Compile C files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Compile C++ files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean
clean:
	rm -f $(OBJECTS) $(TARGET) *.log

# Run with debug
run: $(TARGET)
	./$(TARGET)

# Run with valgrind (memory check)
valgrind: $(TARGET)
	valgrind --leak-check=full ./$(TARGET)

# Debug build
debug: CXXFLAGS += -DDEBUG -g
debug: CFLAGS += -DDEBUG -g
debug: $(TARGET)

# Install dependencies (Ubuntu/Debian)
install-deps:
	sudo apt-get update
	sudo apt-get install -y g++ gcc make libssl-dev

# Install dependencies (Alpine/iSH)
install-deps-alpine:
	apk update
	apk add g++ gcc make openssl-dev libc-dev

.PHONY: all clean run valgrind debug install-deps install-deps-alpine
