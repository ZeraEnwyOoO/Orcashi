 #ifndef ORCASHI_H
#define ORCASHI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>

// ===== ORCASHI Core =====
#include "plug.h"
#include "discovery.h"
#include "registry.h"
#include "request.h"
#include "peer_cache.h"      // ← Add this line!
#include "endpoint.h"
#include "nat_punch.h"
#include "bootstrap.h"
