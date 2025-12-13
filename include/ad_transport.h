/*************************************************
 *************************************************
 **             Name: AD Transport Interface     **
 **             Author: Arkaprava Das            **
 *************************************************
 *************************************************/

#ifndef AD_TRANSPORT_H
#define AD_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include <pthread.h>

#include "../../../prebuilt/inih/include/ini.h"
#include "../../ad_logger/include/ad_logger.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ============================================================
 * Thread-safety contract
 * ============================================================
 *
 * - All public APIs are thread-safe unless stated otherwise.
 * - Peer-table APIs internally acquire locks.
 * - Pointers returned from lookup APIs remain valid only until
 *   the next peer-table mutation.
 * - Transport statistics are returned as snapshots.
 * - Caller must respect buffer ownership rules documented below.
 */

/* ============================================================
 * Transport-level errors
 * ============================================================ */
typedef enum {
    AD_TRANSPORT_OK = 0,
    AD_TRANSPORT_ERR_INVALID_ARGUMENT,
    AD_TRANSPORT_ERR_NO_MEMORY,
    AD_TRANSPORT_ERR_NOT_FOUND,
    AD_TRANSPORT_ERR_EXISTS,
    AD_TRANSPORT_ERR_UNSUPPORTED,
    AD_TRANSPORT_ERR_INTERNAL,
    AD_TRANSPORT_ERR_PEER_TABLE,   /* peer-table failure occurred */
    AD_TRANSPORT_ERR_CONFIG,       /* configuration error */
    AD_TRANSPORT_ERR_IO            /* socket / tun / network error */
} ad_transport_error_t;

/* ============================================================
 * Peer-table specific errors
 * ============================================================ */
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

/* ============================================================
 * Peer definition
 * ============================================================ */
typedef struct {
    char *peer_id;                     /* Unique peer ID (heap-owned) */
    struct sockaddr_in *routes;        /* CIDR routes (masked) */
    uint8_t *route_prefixlen;          /* Prefix length per route */
    size_t route_count;                /* Number of routes */
    struct sockaddr_in real_addr;      /* Real peer endpoint */
    int active;                        /* Active flag (0/1) */
} ad_transport_peer_t;

/* ============================================================
 * Peer table
 * ============================================================ */
typedef struct {
    ad_transport_peer_t *entries;      /* Internal peer array */
    size_t count;                      /* Active peer count */
    size_t capacity;                   /* Allocated capacity */
    unsigned int persist_interval_sec; /* Persistence interval */
    char *db_path;                     /* SQLite DB path (heap-owned) */
    pthread_mutex_t lock;              /* Internal mutex */
} ad_transport_peer_table_t;

/* ============================================================
 * Transport configuration
 * ============================================================ */
typedef struct {
    char *config_path;                 /* INI configuration path */
    char *db_path;                     /* Peer DB path */
    int udp_fd;                        /* Pre-created UDP socket */
    int tun_fd;                        /* Pre-created TUN fd */
    unsigned int persist_interval_sec; /* Persistence interval */
} ad_transport_config_t;

/* ============================================================
 * Transport runtime state
 * ============================================================ */
typedef enum {
    AD_TRANSPORT_STATE_STOPPED,
    AD_TRANSPORT_STATE_RUNNING,
    AD_TRANSPORT_STATE_ERROR
} ad_transport_state_t;

/* ============================================================
 * Transport statistics
 * ============================================================ */
typedef struct {
    uint64_t udp_rx;
    uint64_t udp_tx;
    uint64_t tun_rx;
    uint64_t tun_tx;
    uint64_t dropped_packets;
} ad_transport_stats_t;

/* ============================================================
 * Global peer table accessor (read-only pointer)
 * ============================================================ */
extern ad_transport_peer_table_t *g_ad_global_peer_table;

/* ============================================================
 * Global transport configuration
 * ============================================================ */
extern ad_transport_config_t g_transport_config;

/* ============================================================
 * Transport lifecycle APIs
 * ============================================================ */

/* Initialize transport module with explicit configuration */
ad_transport_error_t
ad_transport_init_with_config(const ad_transport_config_t *cfg);

/* Start transport operations (non-blocking, epoll-driven) */
ad_transport_error_t
ad_transport_start(void);

/* Stop transport operations immediately */
ad_transport_error_t
ad_transport_stop(void);

/* Stop transport operations gracefully (flush + persist) */
ad_transport_error_t
ad_transport_stop_graceful(unsigned int timeout_ms);

/* Restart transport (stop → start) */
ad_transport_error_t
ad_transport_restart(void);

/* Get current transport state */
ad_transport_state_t
ad_transport_get_state(void);

/* ============================================================
 * Transport message APIs
 * ============================================================ */

/* Pack / unpack transport header */
ad_transport_error_t
ad_transport_pack_header(uint8_t *buf, size_t buf_len,
                          uint8_t msg_type, uint16_t msg_len);

ad_transport_error_t
ad_transport_unpack_header(const uint8_t *buf, size_t buf_len,
                            uint8_t *msg_type, uint16_t *msg_len);

/*
 * Read UDP message.
 * Allocates buffer; caller MUST free using ad_transport_free_message().
 */
ad_transport_error_t
ad_transport_read_udp_message(int fd, uint8_t **out_buf, uint16_t *out_len);

/* Write UDP message */
ad_transport_error_t
ad_transport_write_udp_message(int fd, const uint8_t *buf, uint16_t buf_len);

/* Read/write TUN payload */
ad_transport_error_t
ad_transport_read_tun_message(char *buf, size_t buf_len, ssize_t *out_len);

ad_transport_error_t
ad_transport_write_tun_message(const char *buf, size_t buf_len, ssize_t *out_len);

/* Encrypt / decrypt payload */
ad_transport_error_t
ad_transport_encrypt_message(const uint8_t *plaintext, size_t plaintext_len,
                              uint8_t **out_ciphertext,
                              size_t *out_ciphertext_len);

ad_transport_error_t
ad_transport_decrypt_message(const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t **out_plaintext,
                              size_t *out_plaintext_len);

/* Free message buffer allocated by transport */
void
ad_transport_free_message(uint8_t *buf);

/* ============================================================
 * Epoll / event-loop integration
 * ============================================================ */

/* Get transport-owned file descriptors */
ad_transport_error_t
ad_transport_get_udp_fd(int *out_fd);

ad_transport_error_t
ad_transport_get_tun_fd(int *out_fd);

/* Handle readiness events */
ad_transport_error_t
ad_transport_handle_udp_event(void);

ad_transport_error_t
ad_transport_handle_tun_event(void);

/* ============================================================
 * Statistics & observability
 * ============================================================ */
ad_transport_error_t
ad_transport_get_stats(ad_transport_stats_t *out);

/* ============================================================
 * Peer-table APIs
 * ============================================================ */

/* Initialize peer table from INI config */
ad_transport_error_t
ad_transport_peer_table_init_from_config(const char *config_path);

/* Add / remove / update peers */
ad_peer_table_error_t
ad_transport_peer_table_add(ad_transport_peer_t *peer);

ad_peer_table_error_t
ad_transport_peer_table_remove(const char *peer_id);

ad_peer_table_error_t
ad_transport_peer_table_update(ad_transport_peer_t *peer);

ad_peer_table_error_t
ad_transport_peer_table_set_active(const char *peer_id, int active);

ad_peer_table_error_t
ad_transport_peer_table_db_open(const char *path);

ad_peer_table_error_t
ad_transport_peer_table_db_close(void);

/*
 * Lookup by IPv4 address using Longest Prefix Match.
 * Returned pointer is internal; caller must NOT free.
 */
ad_transport_peer_t *
ad_transport_peer_table_lookup(const struct sockaddr_in *addr);

/* Iterate safely over peers */
typedef int (*ad_peer_iter_cb)(
    const ad_transport_peer_t *peer, void *user);

ad_peer_table_error_t
ad_transport_peer_table_foreach(ad_peer_iter_cb cb, void *user);

/* Cleanup peer table */
ad_peer_table_error_t
ad_transport_peer_table_cleanup(void);

/* Read-only access to peer table */
ad_transport_peer_table_t *
ad_transport_get_global_peer_table(void);

/* ============================================================
 * Persistence helpers
 * ============================================================ */
ad_peer_table_error_t
ad_transport_peer_table_db_load(void);

ad_peer_table_error_t
ad_transport_peer_table_db_save(void);

ad_peer_table_error_t
ad_transport_peer_table_start_persistence(void);

ad_peer_table_error_t
ad_transport_peer_table_stop_persistence(void);

/* ============================================================
 * Error mapping
 * ============================================================ */
ad_transport_error_t
ad_transport_map_peer_table_error(ad_peer_table_error_t e);

#ifdef __cplusplus
}
#endif

#endif /* AD_TRANSPORT_H */
