/*************************************************
**************************************************
**             Name: AD Transport Interface     **
**             Author: Arkaprava Das            **
**************************************************
**************************************************/

#ifndef AD_TRANSPORT_H
#define AD_TRANSPORT_H

#include <stdint.h>
#include <netinet/in.h>
#include <pthread.h>
#include "../../../prebuilt/inih/include/ini.h"
#include "../../ad_logger/include/ad_logger.h"
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================
 * Transport-level errors
 * ============================ */
typedef enum {
    AD_TRANSPORT_OK = 0,
    AD_TRANSPORT_ERR_INVALID_ARGUMENT,
    AD_TRANSPORT_ERR_NO_MEMORY,
    AD_TRANSPORT_ERR_NOT_FOUND,
    AD_TRANSPORT_ERR_EXISTS,
    AD_TRANSPORT_ERR_UNSUPPORTED,
    AD_TRANSPORT_ERR_INTERNAL,
    AD_TRANSPORT_ERR_PEER_TABLE,   /* peer-table failure occurred (opaque) */
    AD_TRANSPORT_ERR_CONFIG,       /* config error occurred */
    AD_TRANSPORT_ERR_IO,           /* socket/tun/network failure */
} ad_transport_error_t;

/* ============================
 * Peer-table specific errors
 * (peer-table module / DB)
 * ============================ */
typedef enum {
    AD_PEER_TABLE_OK = 0,
    AD_PEER_TABLE_ERR_FULL,
    AD_PEER_TABLE_ERR_NOT_FOUND,
    AD_PEER_TABLE_ERR_EXISTS,
    AD_PEER_TABLE_ERR_MULTIPLE_MATCH,
    AD_PEER_TABLE_ERR_INTERNAL,
    AD_PEER_TABLE_ERR_NO_MEMORY,
    AD_PEER_TABLE_ERR_INVALID_ARGUMENT,
    AD_PEER_TABLE_ERR_LOCK,
    AD_PEER_TABLE_ERR_UNSUPPORTED,
    AD_PEER_TABLE_ERR_CONFIG_PARSE,
    AD_PEER_TABLE_ERR_CONFIG_INVALID,
    AD_PEER_TABLE_ERR_DB_OPEN,
    AD_PEER_TABLE_ERR_DB_CLOSE,
    AD_PEER_TABLE_ERR_DB_QUERY,
    AD_PEER_TABLE_ERR_DB_WRITE,
    AD_PEER_TABLE_ERR_DB_READ
} ad_peer_table_error_t;


/* Peer entry with multiple CIDR routes */
typedef struct {
    char *peer_id;                     /* Unique ID string (heap str) */
    struct sockaddr_in *routes;        /* Network addresses (masked), length route_count */
    uint8_t *route_prefixlen;          /* Corresponding prefix length for each route */
    size_t route_count;                /* Number of routes */
    struct sockaddr_in real_addr;      /* Real peer endpoint */
    int active;                        /* Active flag */
} ad_transport_peer_t;

/* Peer table */
typedef struct {
    ad_transport_peer_t *entries;      /* Array of peer entries */
    size_t count;                      /* Number of active peers */
    size_t capacity;                   /* Allocated capacity */
    unsigned int persist_interval_sec; /* Persistence interval in seconds */
    char *db_path;                     /* Path to SQLite DB file (heap) */
    pthread_mutex_t lock;              /* Thread safety lock */
} ad_transport_peer_table_t;

/* Global peer table - defined in C file */
extern ad_transport_peer_table_t *g_ad_global_peer_table;
extern sqlite3 *g_db;
extern pthread_t g_persist_thread;
extern volatile int g_run_persist;

/* Initialize peer table from INI config.
 * Returns AD_TRANSPORT_OK on success.
 */
ad_transport_error_t ad_transport_peer_table_init_from_config(const char *config_path);

/* Add a peer (makes internal copies) */
ad_peer_table_error_t ad_transport_peer_table_add(ad_transport_peer_t *peer);

/* Remove a peer by ID */
ad_peer_table_error_t ad_transport_peer_table_remove(const char *peer_id);

/* Lookup by IPv4 address using Longest Prefix Match.
 * Returns pointer to peer on single LPM match.
 * If multiple matches found => returns NULL and sets errno (see implementation comment).
 * If no match => returns NULL and sets errno.
 *
 * NOTE: returned pointer points into the internal table; caller must NOT free it.
 */
ad_transport_peer_t* ad_transport_peer_table_lookup(const struct sockaddr_in *addr);

/* Cleanup global peer table and free memory */
ad_peer_table_error_t ad_transport_peer_table_cleanup(void);

/* Get global peer table pointer (read-only pointer) */
ad_transport_peer_table_t* ad_get_global_peer_table(void);

/* Get a shallow copy of the global peer table metadata (not deep copy).
 * Returned copy.entries points at the live entries array.
 */
ad_transport_peer_table_t ad_get_global_peer_table_copy(void);

/* Database helpers (peer-table DB) */
ad_peer_table_error_t ad_peer_table_db_open(const char *path);
ad_peer_table_error_t ad_peer_table_db_close(void);

ad_peer_table_error_t ad_peer_table_db_load(void);
ad_peer_table_error_t ad_peer_table_db_save(void);

/* Persistence thread control */
ad_peer_table_error_t ad_peer_table_start_persistence(void);
ad_peer_table_error_t ad_peer_table_stop_persistence(void);

/* Small helper to map peer-table error to transport-level (if needed) */
ad_transport_error_t ad_transport_map_peer_table_error(ad_peer_table_error_t e);

#ifdef __cplusplus
}
#endif

#endif /* AD_TRANSPORT_H */
