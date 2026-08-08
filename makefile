 CXX = g++
CXXFLAGS = -std=c++17 -pthread -g -O0
TARGET = orcashi

SOURCES = \
    plug.cpp \
    orcashi.cpp \
    discovery.cpp \
    endpoint.cpp \
    peer_cache.cpp \
    registry.cpp \
    request.cpp \
    dht_wrapper.cpp \
    main.cpp

HEADERS = \
    plug.hpp \
    orcashi.hpp \
    discovery.hpp \
    endpoint.hpp \
    peer_cache.hpp \
    registry.hpp \
    request.hpp \
    dht_wrapper.hpp \
    ui.hpp

OBJECTS = $(SOURCES:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) -o $(TARGET) $(OBJECTS) $(CXXFLAGS) -lssl -lcrypto

%.o: %.cpp $(HEADERS)
	$(CXX) -c $< -o $@ $(CXXFLAGS)

clean:
	rm -f $(TARGET) $(OBJECTS)

rebuild: clean all

.PHONY: all clean rebuild
