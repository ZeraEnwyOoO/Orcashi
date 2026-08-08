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
    dht_libtorrent.cpp \
    main.cpp

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CXX) -o $(TARGET) $(SOURCES) $(CXXFLAGS) -lssl -lcrypto -ltorrent-rasterbar -DTORRENT_USE_OPENSSL

clean:
	rm -f $(TARGET) *.o

.PHONY: all clean
