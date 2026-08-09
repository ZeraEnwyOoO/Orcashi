 /*
Copyright (c) 2009-2011 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

/* Please, please, please.

   You are welcome to integrate this code in your favourite Bittorrent
   client.  Please remember, however, that it is meant to be usable by
   others, including myself.  This means no C++, no relicensing, and no
   gratuitious changes to the coding style.  And please send back any
   improvements to the author. */

/* For memmem. */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>

#if !defined(_WIN32) || defined(__MINGW32__)
#include <sys/time.h>
#endif

#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#else
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501 /* Windows XP */
#endif
#ifndef WINVER
#define WINVER _WIN32_WINNT
#endif
#include <ws2tcpip.h>
#include <windows.h>
#endif

#include "dht.h"

#ifndef HAVE_MEMMEM
#ifdef __GLIBC__
#define HAVE_MEMMEM
#endif
#endif

#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

#if !defined(_WIN32) || defined(__MINGW32__)
#define dht_gettimeofday(_ts, _tz) gettimeofday((_ts), (_tz))
#else
extern int dht_gettimeofday(struct timeval *tv, struct timezone *tz);
#endif

#ifdef _WIN32

#undef EAFNOSUPPORT
#define EAFNOSUPPORT WSAEAFNOSUPPORT

static int
random(void)
{
    return rand();
}

/* Windows Vista and later already provide the implementation. */
#if _WIN32_WINNT < 0x0600
extern const char *inet_ntop(int, const void *, char *, socklen_t);
#endif

#ifdef _MSC_VER
/* There is no snprintf in MSVCRT. */
#define snprintf _snprintf
#endif

#endif

/* We set sin_family to 0 to mark unused slots. */
#if AF_INET == 0 || AF_INET6 == 0
#error You lose
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
/* nothing */
#elif defined(__GNUC__)
#define inline __inline
#if  (__GNUC__ >= 3)
#define restrict __restrict
#else
#define restrict /**/
#endif
#else
#define inline /**/
#define restrict /**/
#endif

#define MAX(x, y) ((x) >= (y) ? (x) : (y))
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

struct node {
    unsigned char id[20];
    struct sockaddr_storage ss;
    int sslen;
    time_t time;                /* time of last message received */
    time_t reply_time;          /* time of last correct reply received */
    time_t pinged_time;         /* time of last request */
    int pinged;                 /* how many requests we sent since last reply */
    struct node *next;
};

struct bucket {
    int af;
    unsigned char first[20];
    int count;                  /* number of nodes */
    int max_count;              /* max number of nodes for this bucket */
    time_t time;                /* time of last reply in this bucket */
    struct node *nodes;
    struct sockaddr_storage cached;  /* the address of a likely candidate */
    int cachedlen;
    struct bucket *next;
};

struct search_node {
    unsigned char id[20];
    struct sockaddr_storage ss;
    int sslen;
    time_t request_time;        /* the time of the last unanswered request */
    time_t reply_time;          /* the time of the last reply */
    int pinged;
    unsigned char token[40];
    int token_len;
    int replied;                /* whether we have received a reply */
    int acked;                  /* whether they acked our announcement */
};

/* When performing a search, we search for up to SEARCH_NODES closest nodes
   to the destination, and use the additional ones to backtrack if any of
   the target 8 turn out to be dead. */
#define SEARCH_NODES 14

struct search {
    unsigned short tid;
    int af;
    time_t step_time;           /* the time of the last search_step */
    unsigned char id[20];
    unsigned short port;        /* 0 for pure searches */
    int done;
    struct search_node nodes[SEARCH_NODES];
    int numnodes;
    struct search *next;
};

struct peer {
    time_t time;
    unsigned char ip[16];
    unsigned short len;
    unsigned short port;
};

/* The maximum number of peers we store for a given hash. */
#ifndef DHT_MAX_PEERS
#define DHT_MAX_PEERS 2048
#endif

/* The maximum number of hashes we're willing to track. */
#ifndef DHT_MAX_HASHES
#define DHT_MAX_HASHES 16384
#endif

/* The maximum number of searches we keep data about. */
#ifndef DHT_MAX_SEARCHES
#define DHT_MAX_SEARCHES 1024
#endif

/* The time after which we consider a search to be expirable. */
#ifndef DHT_SEARCH_EXPIRE_TIME
#define DHT_SEARCH_EXPIRE_TIME (62 * 60)
#endif

/* The maximum number of in-flight queries per search. */
#ifndef DHT_INFLIGHT_QUERIES
#define DHT_INFLIGHT_QUERIES 4
#endif

/* The retransmit timeout when performing searches. */
#ifndef DHT_SEARCH_RETRANSMIT
#define DHT_SEARCH_RETRANSMIT 10
#endif

struct storage {
    unsigned char id[20];
    int numpeers, maxpeers;
    struct peer *peers;
    struct storage *next;
};

static struct storage * find_storage(const unsigned char *id);
static void flush_search_node(struct search_node *n, struct search *sr);

static int send_ping(const struct sockaddr *sa, int salen,
                     const unsigned char *tid, int tid_len);
static int send_pong(const struct sockaddr *sa, int salen,
                     const unsigned char *tid, int tid_len);
static int send_find_node(const struct sockaddr *sa, int salen,
                          const unsigned char *tid, int tid_len,
                          const unsigned char *target, int want, int confirm);
static int send_nodes_peers(const struct sockaddr *sa, int salen,
                            const unsigned char *tid, int tid_len,
                            const unsigned char *nodes, int nodes_len,
                            const unsigned char *nodes6, int nodes6_len,
                            int af, struct storage *st,
                            const unsigned char *token, int token_len);
static int send_closest_nodes(const struct sockaddr *sa, int salen,
                              const unsigned char *tid, int tid_len,
                              const unsigned char *id, int want,
                              int af, struct storage *st,
                              const unsigned char *token, int token_len);
static int send_get_peers(const struct sockaddr *sa, int salen,
                          unsigned char *tid, int tid_len,
                          unsigned char *infohash, int want, int confirm);
static int send_announce_peer(const struct sockaddr *sa, int salen,
                              unsigned char *tid, int tid_len,
                              unsigned char *infohas, unsigned short port,
                              unsigned char *token, int token_len, int confirm);
static int send_peer_announced(const struct sockaddr *sa, int salen,
                               unsigned char *tid, int tid_len);
static int send_error(const struct sockaddr *sa, int salen,
                      unsigned char *tid, int tid_len,
                      int code, const char *message);

static void
add_search_node(const unsigned char *id, const struct sockaddr *sa, int salen);

#define ERROR 0
#define REPLY 1
#define PING 2
#define FIND_NODE 3
#define GET_PEERS 4
#define ANNOUNCE_PEER 5

#define WANT4 1
#define WANT6 2

#define PARSE_TID_LEN 16
#define PARSE_TOKEN_LEN 128
#define PARSE_NODES_LEN (26 * 16)
#define PARSE_NODES6_LEN (38 * 16)
#define PARSE_VALUES_LEN 2048
#define PARSE_VALUES6_LEN 2048

struct parsed_message {
    unsigned char tid[PARSE_TID_LEN];
    unsigned short tid_len;
    unsigned char id[20];
    unsigned char info_hash[20];
    unsigned char target[20];
    unsigned short port;
    unsigned short implied_port;
    unsigned char token[PARSE_TOKEN_LEN];
    unsigned short token_len;
    unsigned char nodes[PARSE_NODES_LEN];
    unsigned short nodes_len;
    unsigned char nodes6[PARSE_NODES6_LEN];
    unsigned short nodes6_len;
    unsigned char values[PARSE_VALUES_LEN];
    unsigned short values_len;
    unsigned char values6[PARSE_VALUES6_LEN];
    unsigned short values6_len;
    unsigned short want;
};

static int parse_message(const unsigned char *buf, int buflen,
                         struct parsed_message *m);

static const unsigned char zeroes[20] = {0};
static const unsigned char v4prefix[16] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0
};

static int dht_socket = -1;
static int dht_socket6 = -1;

static time_t search_time;
static time_t confirm_nodes_time;
static time_t rotate_secrets_time;

static unsigned char myid[20];
static int have_v = 0;
static unsigned char my_v[9];
static unsigned char secret[8];
static unsigned char oldsecret[8];

static struct bucket *buckets = NULL;
static struct bucket *buckets6 = NULL;
static struct storage *storage;
static int numstorage;

static struct search *searches = NULL;
static int numsearches;
static unsigned short search_id;

/* The maximum number of nodes that we snub.  There is probably little
   reason to increase this value. */
#ifndef DHT_MAX_BLACKLISTED
#define DHT_MAX_BLACKLISTED 10
#endif
static struct sockaddr_storage blacklist[DHT_MAX_BLACKLISTED];
int next_blacklisted;

static struct timeval now;
static time_t mybucket_grow_time, mybucket6_grow_time;
static time_t expire_stuff_time;

#define MAX_TOKEN_BUCKET_TOKENS 400
static time_t token_bucket_time;
static int token_bucket_tokens;

FILE *dht_debug = NULL;

#ifdef __GNUC__
    __attribute__ ((format (printf, 1, 2)))
#endif
static void
debugf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    if(dht_debug)
        vfprintf(dht_debug, format, args);
    va_end(args);
    if(dht_debug)
        fflush(dht_debug);
}

static void
debug_printable(const unsigned char *buf, int buflen)
{
    int i;
    if(dht_debug) {
        for(i = 0; i < buflen; i++)
            putc(buf[i] >= 32 && buf[i] <= 126 ? buf[i] : '.', dht_debug);
    }
}

static void
print_hex(FILE *f, const unsigned char *buf, int buflen)
{
    int i;
    for(i = 0; i < buflen; i++)
        fprintf(f, "%02x", buf[i]);
}

static int
is_martian(const struct sockaddr *sa)
{
    switch(sa->sa_family) {
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in*)sa;
        const unsigned char *address = (const unsigned char*)&sin->sin_addr;
        return sin->sin_port == 0 ||
            (address[0] == 0) ||
            (address[0] == 127) ||
            ((address[0] & 0xE0) == 0xE0);
    }
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)sa;
        const unsigned char *address = (const unsigned char*)&sin6->sin6_addr;
        return sin6->sin6_port == 0 ||
            (address[0] == 0xFF) ||
            (address[0] == 0xFE && (address[1] & 0xC0) == 0x80) ||
            (memcmp(address, zeroes, 15) == 0 &&
             (address[15] == 0 || address[15] == 1)) ||
            (memcmp(address, v4prefix, 12) == 0);
    }

    default:
        return 0;
    }
}

/* Forget about the ``XOR-metric''.  An id is just a path from the
   root of the tree, so bits are numbered from the start. */

static int
id_cmp(const unsigned char *restrict id1, const unsigned char *restrict id2)
{
    /* Memcmp is guaranteed to perform an unsigned comparison. */
    return memcmp(id1, id2, 20);
}

/* Find the lowest 1 bit in an id. */
static int
lowbit(const unsigned char *id)
{
    int i, j;
    for(i = 19; i >= 0; i--)
        if(id[i] != 0)
            break;

    if(i < 0)
        return -1;

    for(j = 7; j >= 0; j--)
        if((id[i] & (0x80 >> j)) != 0)
            break;

    return 8 * i + j;
}

/* Find how many bits two ids have in common. */
static int
common_bits(const unsigned char *id1, const unsigned char *id2)
{
    int i, j;
    unsigned char x_or;
    for(i = 0; i < 20; i++) {
        if(id1[i] != id2[i])
            break;
    }

    if(i == 20)
        return 160;

    x_or = id1[i] ^ id2[i];

    j = 0;
    while((x_or & 0x80) == 0) {
        x_or <<= 1;
        j++;
    }

    return 8 * i + j;
}

/* Determine whether id1 or id2 is closer to ref */
static int
xorcmp(const unsigned char *id1, const unsigned char *id2,
       const unsigned char *ref)
{
    int i;
    for(i = 0; i < 20; i++) {
        unsigned char xor1, xor2;
        if(id1[i] == id2[i])
            continue;
        xor1 = id1[i] ^ ref[i];
        xor2 = id2[i] ^ ref[i];
        if(xor1 < xor2)
            return -1;
        else
            return 1;
    }
    return 0;
}

/* We keep buckets in a sorted linked list.  A bucket b ranges from
   b->first inclusive up to b->next->first exclusive. */
static int
in_bucket(const unsigned char *id, struct bucket *b)
{
    return id_cmp(b->first, id) <= 0 &&
        (b->next == NULL || id_cmp(id, b->next->first) < 0);
}

static struct bucket *
find_bucket(unsigned const char *id, int af)
{
    struct bucket *b = af == AF_INET ? buckets : buckets6;

    if(b == NULL)
        return NULL;

    while(1) {
        if(b->next == NULL)
            return b;
        if(id_cmp(id, b->next->first) < 0)
            return b;
        b = b->next;
    }
}

static struct bucket *
previous_bucket(struct bucket *b)
{
    struct bucket *p = b->af == AF_INET ? buckets : buckets6;

    if(b == p)
        return NULL;

    while(1) {
        if(p->next == NULL)
            return NULL;
        if(p->next == b)
            return p;
        p = p->next;
    }
}

/* Every bucket contains an unordered list of nodes. */
static struct node *
find_node(const unsigned char *id, int af)
{
    struct bucket *b = find_bucket(id, af);
    struct node *n;

    if(b == NULL)
        return NULL;

    n = b->nodes;
    while(n) {
        if(id_cmp(n->id, id) == 0)
            return n;
        n = n->next;
    }
    return NULL;
}

/* Return a random node in a bucket. */
static struct node *
random_node(struct bucket *b)
{
    struct node *n;
    int nn;

    if(b->count == 0)
        return NULL;

    nn = random() % b->count;
    n = b->nodes;
    while(nn > 0 && n) {
        n = n->next;
        nn--;
    }
    return n;
}

/* Return the middle id of a bucket. */
static int
bucket_middle(struct bucket *b, unsigned char *id_return)
{
    int bit1 = lowbit(b->first);
    int bit2 = b->next ? lowbit(b->next->first) : -1;
    int bit = MAX(bit1, bit2) + 1;

    if(bit >= 160)
        return -1;

    memcpy(id_return, b->first, 20);
    id_return[bit / 8] |= (0x80 >> (bit % 8));
    return 1;
}

/* Return a random id within a bucket. */
static int
bucket_random(struct bucket *b, unsigned char *id_return)
{
    int bit1 = lowbit(b->first);
    int bit2 = b->next ? lowbit(b->next->first) : -1;
    int bit = MAX(bit1, bit2) + 1;
    int i;

    if(bit >= 160) {
        memcpy(id_return, b->first, 20);
        return 1;
    }

    memcpy(id_return, b->first, bit / 8);
    id_return[bit / 8] = b->first[bit / 8] & (0xFF00 >> (bit % 8));
    id_return[bit / 8] |= random() & 0xFF >> (bit % 8);
    for(i = bit / 8 + 1; i < 20; i++)
        id_return[i] = random() & 0xFF;
    return 1;
}

/* This is our definition of a known-good node. */
static int
node_good(struct node *node)
{
    return
        node->pinged <= 2 &&
        node->reply_time >= now.tv_sec - 7200 &&
        node->time >= now.tv_sec - 900;
}

/* Our transaction-ids are 4-bytes long, with the first two bytes identi-
   fying the kind of request, and the remaining two a sequence number in
   host order. */

static void
make_tid(unsigned char *tid_return, const char *prefix, unsigned short seqno)
{
    tid_return[0] = prefix[0] & 0xFF;
    tid_return[1] = prefix[1] & 0xFF;
    memcpy(tid_return + 2, &seqno, 2);
}

static int
tid_match(const unsigned char *tid, const char *prefix,
          unsigned short *seqno_return)
{
    if(tid[0] == (prefix[0] & 0xFF) && tid[1] == (prefix[1] & 0xFF)) {
        if(seqno_return)
            memcpy(seqno_return, tid + 2, 2);
        return 1;
    } else
        return 0;
}

/* Every bucket caches the address of a likely node.  Ping it. */
static int
send_cached_ping(struct bucket *b)
{
    unsigned char tid[4];
    int rc;
    /* We set family to 0 when there's no cached node. */
    if(b->cached.ss_family == 0)
        return 0;

    debugf("Sending ping to cached node.\n");
    make_tid(tid, "pn", 0);
    rc = send_ping((struct sockaddr*)&b->cached, b->cachedlen, tid, 4);
    b->cached.ss_family = 0;
    b->cachedlen = 0;
    return rc;
}

/* Called whenever we send a request to a node, increases the ping count
   and, if that reaches 3, sends a ping to a new candidate. */
static void
pinged(struct node *n, struct bucket *b)
{
    n->pinged++;
    n->pinged_time = now.tv_sec;
    if(n->pinged >= 3)
        send_cached_ping(b ? b : find_bucket(n->id, n->ss.ss_family));
}

/* The internal blacklist is an LRU cache of nodes that have sent
   incorrect messages. */
static void
blacklist_node(const unsigned char *id, const struct sockaddr *sa, int salen)
{
    int i;

    debugf("Blacklisting broken node.\n");

    if(id) {
        struct node *n;
        struct search *sr;
        /* Make the node easy to discard. */
        n = find_node(id, sa->sa_family);
        if(n) {
            n->pinged = 3;
            pinged(n, NULL);
        }
        /* Discard it from any searches in progress. */
        sr = searches;
        while(sr) {
            for(i = 0; i < sr->numnodes; i++)
                if(id_cmp(sr->nodes[i].id, id) == 0)
                    flush_search_node(&sr->nodes[i], sr);
            sr = sr->next;
        }
    }
    /* And make sure we don't hear from it again. */
    memcpy(&blacklist[next_blacklisted], sa, salen);
    next_blacklisted = (next_blacklisted + 1) % DHT_MAX_BLACKLISTED;
}

static int
node_blacklisted(const struct sockaddr *sa, int salen)
{
    int i;

    if((unsigned)salen > sizeof(struct sockaddr_storage))
        abort();

    if(dht_blacklisted(sa, salen))
        return 1;

    for(i = 0; i < DHT_MAX_BLACKLISTED; i++) {
        if(memcmp(&blacklist[i], sa, salen) == 0)
            return 1;
    }

    return 0;
}

static struct node *
append_nodes(struct node *n1, struct node *n2)
{
    struct node *n;

    if(n1 == NULL)
        return n2;

    if(n2 == NULL)
        return n1;

    n = n1;
    while(n->next != NULL)
        n = n->next;

    n->next = n2;
    return n1;
}

/* Insert a new node into a bucket, don't check for duplicates.
   Returns 1 if the node was inserted, 0 if a bucket must be split. */
static int
insert_node(struct node *node, struct bucket **split_return)
{
    struct bucket *b = find_bucket(node->id, node->ss.ss_family);

    if(b == NULL)
        return -1;

    if(b->count >= b->max_count) {
        *split_return = b;
        return 0;
    }
    node->next = b->nodes;
    b->nodes = node;
    b->count++;
    return 1;
}

/* Splits a bucket, and returns the list of nodes that must be reinserted
   into the routing table. */
static int
split_bucket_helper(struct bucket *b, struct node **nodes_return)
{
    struct bucket *new_bucket;
    int rc;
    unsigned char new_id[20];

    if(!in_bucket(myid, b)) {
        debugf("Attempted to split wrong bucket.\n");
        return -1;
    }

    rc = bucket_middle(b, new_id);
    if(rc < 0)
        return -1;

    new_bucket = (struct bucket*)calloc(1, sizeof(struct bucket));
    if(new_bucket == NULL)
        return -1;

    send_cached_ping(b);

    new_bucket->af = b->af;
    memcpy(new_bucket->first, new_id, 20);
    new_bucket->time = b->time;

    *nodes_return = b->nodes;
    b->nodes = NULL;
    b->count = 0;
    new_bucket->next = b->next;
    b->next = new_bucket;

    if(in_bucket(myid, b)) {
        new_bucket->max_count = b->max_count;
        b->max_count = MAX(b->max_count / 2, 8);
    } else {
        new_bucket->max_count = MAX(b->max_count / 2, 8);
    }

    return 1;
}

static int
split_bucket(struct bucket *b)
{
    int rc;
    struct node *nodes = NULL;
    struct node *n = NULL;

    debugf("Splitting.\n");
    rc = split_bucket_helper(b, &nodes);
    if(rc < 0) {
        debugf("Couldn't split bucket");
        return -1;
    }

    while(n != NULL || nodes != NULL) {
        struct bucket *split = NULL;
        if(n == NULL) {
            n = nodes;
            nodes = nodes->next;
            n->next = NULL;
        }
        rc = insert_node(n, &split);
        if(rc < 0) {
            debugf("Couldn't insert node.\n");
            free(n);
            n = NULL;
        } else if(rc > 0) {
            n = NULL;
        } else if(!in_bucket(myid, split)) {
            free(n);
            n = NULL;
        } else {
            struct node *insert = NULL;
            debugf("Splitting (recursive).\n");
            rc = split_bucket_helper(split, &insert);
            if(rc < 0) {
                debugf("Couldn't split bucket.\n");
                free(n);
                n = NULL;
            } else {
                nodes = append_nodes(nodes, insert);
            }
        }
    }
    return 1;
}

/* We just learnt about a node, not necessarily a new one.  Confirm is 1 if
   the node sent a message, 2 if it sent us a reply. */
static struct node *
new_node(const unsigned char *id, const struct sockaddr *sa, int salen,
         int confirm)
{
    struct bucket *b;
    struct node *n;
    int mybucket;

 again:

    b = find_bucket(id, sa->sa_family);
    if(b == NULL)
        return NULL;

    if(id_cmp(id, myid) == 0)
        return NULL;

    if(is_martian(sa) || node_blacklisted(sa, salen))
        return NULL;

    mybucket = in_bucket(myid, b);

    if(confirm == 2)
        b->time = now.tv_sec;

    n = b->nodes;
    while(n) {
        if(id_cmp(n->id, id) == 0) {
            if(confirm || n->time < now.tv_sec - 15 * 60) {
                /* Known node.  Update stuff. */
                memcpy((struct sockaddr*)&n->ss, sa, salen);
                if(confirm)
                    n->time = now.tv_sec;
                if(confirm >= 2) {
                    n->reply_time = now.tv_sec;
                    n->pinged = 0;
                    n->pinged_time = 0;
                }
            }
            if(confirm == 2)
                add_search_node(id, sa, salen);
            return n;
        }
        n = n->next;
    }

    /* New node. */

    if(mybucket) {
        if(sa->sa_family == AF_INET)
            mybucket_grow_time = now.tv_sec;
        else
            mybucket6_grow_time = now.tv_sec;
    }

    /* First, try to get rid of a known-bad node. */
    n = b->nodes;
    while(n) {
        if(n->pinged >= 3 && n->pinged_time < now.tv_sec - 15) {
            memcpy(n->id, id, 20);
            memcpy((struct sockaddr*)&n->ss, sa, salen);
            n->time = confirm ? now.tv_sec : 0;
            n->reply_time = confirm >= 2 ? now.tv_sec : 0;
            n->pinged_time = 0;
            n->pinged = 0;
            if(confirm == 2)
                add_search_node(id, sa, salen);
            return n;
        }
        n = n->next;
    }

    if(b->count >= b->max_count) {
        /* Bucket full.  Ping a dubious node */
        int dubious = 0;
        n = b->nodes;
        while(n) {
            /* Pick the first dubious node that we haven't pinged in the
               last 15 seconds.  This gives nodes the time to reply, but
               tends to concentrate on the same nodes, so that we get rid
               of bad nodes fast. */
            if(!node_good(n)) {
                dubious = 1;
                if(n->pinged_time < now.tv_sec - 15) {
                    unsigned char tid[4];
                    debugf("Sending ping to dubious node.\n");
                    make_tid(tid, "pn", 0);
                    send_ping((struct sockaddr*)&n->ss, n->sslen,
                              tid, 4);
                    n->pinged++;
                    n->pinged_time = now.tv_sec;
                    break;
                }
            }
            n = n->next;
        }

        if(mybucket && !dubious) {
            int rc;
            rc = split_bucket(b);
            if(rc > 0)
                goto again;
            return NULL;
        }

        /* No space for this node.  Cache it away for later. */
        if(confirm || b->cached.ss_family == 0) {
            memcpy(&b->cached, sa, salen);
            b->cachedlen = salen;
        }

        if(confirm == 2)
            add_search_node(id, sa, salen);
        return NULL;
    }

    /* Create a new node. */
    n = (struct node*)calloc(1, sizeof(struct node));
    if(n == NULL)
        return NULL;
    memcpy(n->id, id, 20);
    memcpy(&n->ss, sa, salen);
    n->sslen = salen;
    n->time = confirm ? now.tv_sec : 0;
    n->reply_time = confirm >= 2 ? now.tv_sec : 0;
    n->next = b->nodes;
    b->nodes = n;
    b->count++;
    if(confirm == 2)
        add_search_node(id, sa, salen);
    return n;
}

/* Called periodically to purge known-bad nodes.  Note that we're very
   conservative here: broken nodes in the table don't do much harm, we'll
   recover as soon as we find better ones. */
static int
expire_buckets(struct bucket *b)
{
    while(b) {
        struct node *n, *p;
        int changed = 0;

        while(b->nodes && b->nodes->pinged >= 4) {
            n = b->nodes;
            b->nodes = n->next;
            b->count--;
            changed = 1;
            free(n);
        }

        p = b->nodes;
        while(p) {
            while(p->next && p->next->pinged >= 4) {
                n = p->next;
                p->next = n->next;
                b->count--;
                changed = 1;
                free(n);
            }
            p = p->next;
        }

        if(changed)
            send_cached_ping(b);

        b = b->next;
    }
    expire_stuff_time = now.tv_sec + 120 + random() % 240;
    return 1;
}

/* While a search is in progress, we don't necessarily keep the nodes being
   walked in the main bucket table.  A search in progress is identified by
   a unique transaction id, a short (and hence small enough to fit in the
   transaction id of the protocol packets). */

static struct search *
find_search(unsigned short tid, int af)
{
    struct search *sr = searches;
    while(sr) {
        if(sr->tid == tid && sr->af == af)
            return sr;
        sr = sr->next;
    }
    return NULL;
}

/* A search contains a list of nodes, sorted by decreasing distance to the
   target.  We just got a new candidate, insert it at the right spot or
   discard it. */

static struct search_node*
insert_search_node(const unsigned char *id,
                   const struct sockaddr *sa, int salen,
                   struct search *sr, int replied,
                   unsigned char *token, int token_len)
{
    struct search_node *n;
    int i, j;

    if(sa->sa_family != sr->af) {
        debugf("Attempted to insert node in the wrong family.\n");
        return NULL;
    }

    for(i = 0; i < sr->numnodes; i++) {
        if(id_cmp(id, sr->nodes[i].id) == 0) {
            n = &sr->nodes[i];
            goto found;
        }
        if(xorcmp(id, sr->nodes[i].id, sr->id) < 0)
            break;
    }

    if(i == SEARCH_NODES)
        return NULL;

    if(sr->numnodes < SEARCH_NODES)
        sr->numnodes++;

    for(j = sr->numnodes - 1; j > i; j--) {
        sr->nodes[j] = sr->nodes[j - 1];
    }

    n = &sr->nodes[i];

    memset(n, 0, sizeof(struct search_node));
    memcpy(n->id, id, 20);

found:
    memcpy(&n->
