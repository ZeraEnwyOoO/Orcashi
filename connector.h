#ifndef CONNECTOR_H
#define CONNECTOR_H

#include <stdbool.h>

typedef struct Connector Connector;
typedef struct ORCASHI ORCASHI;

// ===== Create / Destroy =====
Connector* connector_create(ORCASHI* orcashi);
void connector_destroy(Connector* connector);

// ===== Connect =====
bool connector_connect(Connector* connector, const char* id);
bool connector_connect_direct(Connector* connector, const char* ip, int port);

// ===== Status =====
bool connector_is_connected(Connector* connector);

#endif
