# Makefile for ORCASHI v3.1
CXX = g++
CXXFLAGS = -std=c++17 -pthread -g -O0
TARGET = orcashi

# Source files
SOURCES = \
    plug.cpp \
    orcashi.cpp \
    discovery.cpp \
    endpoint.cpp \
    peer_cache.cpp \
    registry.cpp \
    request.cpp \
    mdns.cpp \
    main.cpp

# Header files
HEADERS = \
    plug.hpp \
    orcashi.hpp \
    discovery.hpp \
    endpoint.hpp \
    peer_cache.hpp \
    registry.hpp \
    request.hpp \
    mdns.hpp \
    ui.hpp

# Object files
OBJECTS = $(SOURCES:.cpp=.o)

# Default target
all: $(TARGET)

# Link object files to create executable
$(TARGET): $(OBJECTS)
	$(CXX) -o $(TARGET) $(OBJECTS) $(CXXFLAGS)

# Compile source files to object files
%.o: %.cpp $(HEADERS)
	$(CXX) -c $< -o $@ $(CXXFLAGS)

# Clean up
clean:
	rm -f $(TARGET) $(OBJECTS)

# Clean and rebuild
rebuild: clean all

# Run with debug
debug: $(TARGET)
	gdb ./$(TARGET)

# Install (copy to /usr/local/bin)
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

# Uninstall
uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)

# Help
help:
	@echo "ORCASHI Makefile"
	@echo ""
	@echo "  make          - Compile ORCASHI"
	@echo "  make clean    - Remove object files and binary"
	@echo "  make rebuild  - Clean and rebuild"
	@echo "  make debug    - Run with GDB"
	@echo "  make install  - Install to /usr/local/bin"
	@echo "  make uninstall - Remove from /usr/local/bin"
	@echo "  make help     - Show this help"

.PHONY: all clean rebuild debug install uninstall help
