/*************************************************
**************************************************
**          Name: AD Transport Implementation   **
**          Author: Arkaprava Das               **
**************************************************
**************************************************/

#include "../include/ad_transport.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>     /* sleep */
#include <ctype.h>      /* isspace */

/* ============================
 * Logging Macros are expected
 * to be visible via ad_logger include
 * Use your AD_LOG_TRANSPORT_* macros
 * ============================ */

/* Defaults */
#define DEFAULT_INITIAL_CAPACITY 16
#define DEFAULT_PERSIST_INTERVAL_SEC 120

/* Global definitions (previously were static in header) */
ad_transport_peer_table_t *g_ad_global_peer_table = NULL;
sqlite3 *g_db = NULL;
pthread_t g_persist_thread = 0;
volatile int g_run_persist = 0;

/* ---------------------------
 * Internal helpers
 * --------------------------- */

/* Trim left/right */
static char *trim(char *s)
{
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

/* Parse CIDR string into sockaddr_in and prefix length */
static int parse_cidr(const char *cidr, struct sockaddr_in *addr, uint8_t *prefixlen)
{
    if (!cidr || !addr || !prefixlen) return -1;
    char buf[64];
    strncpy(buf, cidr, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';
    char *s = trim(buf);

    char *slash = strchr(s, '/');
    if (!slash) return -1;
    *slash = '\0';
    slash++;
    int preflen = atoi(slash);
    if (preflen < 0 || preflen > 32) return -1;

    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    if (inet_pton(AF_INET, s, &addr->sin_addr) != 1) return -1;

    *prefixlen = (uint8_t)preflen;
    return 0;
}

/* Make mask compare safe across network order */
static inline int match_ipv4_prefix(uint32_t ip, uint32_t net, uint8_t prefix)
{
    if (prefix == 0) return 1; /* default route matches all */
    uint32_t hostmask;
    if (prefix == 32) hostmask = 0xFFFFFFFFu;
    else hostmask = (~0u) << (32 - prefix);
    uint32_t mask = htonl(hostmask); /* convert to network order */
    return (ip & mask) == (net & mask);
}

/* Find LPM match in single peer */
static int peer_match_lpm(const ad_transport_peer_t *peer, uint32_t ip,
                          const struct sockaddr_in **best_route_out, uint8_t *best_prefix_out)
{
    if (!peer || peer->route_count == 0) return 0;

    int best_prefix = -1;
    int best_count = 0;
    const struct sockaddr_in *best_route = NULL;

    for (size_t i = 0; i < peer->route_count; i++) {
        uint32_t net = peer->routes[i].sin_addr.s_addr;
        uint8_t prefix = peer->route_prefixlen[i];

        if (match_ipv4_prefix(ip, net, prefix)) {
            if ((int)prefix > best_prefix) {
                best_prefix = prefix;
                best_route = &peer->routes[i];
                best_count = 1;
            } else if ((int)prefix == best_prefix) {
                best_count++;
            }
        }
    }

    if (best_prefix < 0) return 0;         /* no match */
    if (best_count > 1) return -1;         /* conflict */
    if (best_route_out) *best_route_out = best_route;
    if (best_prefix_out) *best_prefix_out = (uint8_t)best_prefix;
    return 1;
}

/* Append route to a peer object (used by DB load or parsing before add) */
static int add_route_to_peer(ad_transport_peer_t *peer, struct sockaddr_in addr, uint8_t prefix)
{
    if (!peer) return -1;
    size_t new_count = peer->route_count + 1;
    struct sockaddr_in *nroutes = realloc(peer->routes, new_count * sizeof(*nroutes));
    uint8_t *nprefix = realloc(peer->route_prefixlen, new_count * sizeof(*nprefix));
    if (!nroutes || !nprefix) {
        free(nroutes);
        free(nprefix);
        return -1;
    }
    peer->routes = nroutes;
    peer->route_prefixlen = nprefix;
    peer->routes[peer->route_count] = addr;
    peer->route_prefixlen[peer->route_count] = prefix;
    peer->route_count = new_count;
    return 0;
}

/* Create "x.x.x.x/len" string in caller-provided buffer */
static void make_cidr_string(const struct sockaddr_in *addr, uint8_t prefix, char *buf, size_t bufsz)
{
    if (!addr || !buf) {
        if (buf && bufsz) buf[0] = '\0';
        return;
    }
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    snprintf(buf, bufsz, "%s/%u", ip, (unsigned)prefix);
}

/* ---------------------------
 * INI parsing context
 * --------------------------- */
typedef struct {
    unsigned int persist_interval_sec;
    char *db_path;                 /* duplicated */
    unsigned int initial_capacity;

    /* current parsing peer (accumulates values for one peer section) */
    ad_transport_peer_t current_peer;
    struct sockaddr_in *routes_tmp;
    uint8_t *prefix_tmp;
    size_t route_count;
    size_t route_cap;

    char *last_section; /* strdup of last section name to detect section changes */
} ini_peer_ctx_t;

/* Helper to reset current_peer storage in ctx (frees temp arrays and peer_id if requested) */
static void ini_ctx_reset_peer(ini_peer_ctx_t *ctx, int free_peer_id)
{
    if (!ctx) return;
    if (free_peer_id && ctx->current_peer.peer_id) {
        free(ctx->current_peer.peer_id);
        ctx->current_peer.peer_id = NULL;
    }
    free(ctx->routes_tmp); ctx->routes_tmp = NULL;
    free(ctx->prefix_tmp); ctx->prefix_tmp = NULL;
    ctx->route_count = 0;
    ctx->route_cap = 0;
    ctx->current_peer.route_count = 0;
}

/* Forward declaration of add-to-table: used by ad_transport_ini_handler to commit peers */
static ad_peer_table_error_t commit_current_peer(ini_peer_ctx_t *ctx);

/* INI handler callback */
static int ad_transport_ini_handler(void* user, const char* section, const char* name, const char* value)
{
    ini_peer_ctx_t *ctx = (ini_peer_ctx_t*)user;
    if (!ctx || !section || !name) return 0;

    /* peer_table block */
    if (strcmp(section, "peer_table") == 0) {
        if (strcmp(name, "capacity") == 0) {
            ctx->initial_capacity = (unsigned int)atoi(value);
        } else if (strcmp(name, "persist_interval") == 0) {
            ctx->persist_interval_sec = (unsigned int)atoi(value);
        } else if (strcmp(name, "db_path") == 0) {
            free(ctx->db_path);
            ctx->db_path = strdup(value);
        }
        return 1;
    }

    /* peer sections */
    if (strncmp(section, "peer:", 5) == 0) {
        /* detect section change: if last_section differs, commit previous peer */
        if (!ctx->last_section || strcmp(ctx->last_section, section) != 0) {
            /* commit previous */
            if (ctx->current_peer.peer_id) {
                if (commit_current_peer(ctx) != AD_PEER_TABLE_OK) {
                    AD_LOG_TRANSPORT_ERROR("Failed to commit peer %s from INI", ctx->current_peer.peer_id);
                    /* continue parsing but indicate failure by returning 0? return 0 would abort parse.
                       We'll return 1 to continue parsing remaining peers. */
                }
            }
            free(ctx->last_section);
            ctx->last_section = strdup(section);
            /* initialize new peer */
            ini_ctx_reset_peer(ctx, 0);
            memset(&ctx->current_peer, 0, sizeof(ctx->current_peer));
            ctx->current_peer.peer_id = strdup(section + 5); /* everything after "peer:" */
            ctx->current_peer.active = 0;
        }

        /* now handle the key of the current peer section */
        if (strcmp(name, "real_addr") == 0) {
            char buf[64];
            strncpy(buf, value, sizeof(buf)-1);
            buf[sizeof(buf)-1] = '\0';
            char *s = trim(buf);
            char *colon = strrchr(s, ':');
            if (colon) {
                *colon = '\0';
                int port = atoi(colon + 1);
                ctx->current_peer.real_addr.sin_port = htons((uint16_t)port);
            }
            ctx->current_peer.real_addr.sin_family = AF_INET;
            if (inet_pton(AF_INET, s, &ctx->current_peer.real_addr.sin_addr) != 1) {
                AD_LOG_TRANSPORT_WARN("Invalid real_addr '%s' for peer %s", value, ctx->current_peer.peer_id);
            }
        }
        else if (strcmp(name, "routes") == 0) {
            char buf[1024];
            strncpy(buf, value, sizeof(buf)-1);
            buf[sizeof(buf)-1] = '\0';
            char *save = NULL;
            char *tok = strtok_r(buf, ",", &save);
            while (tok) {
                char *t = trim(tok);
                if (ctx->route_count >= ctx->route_cap) {
                    size_t nc = ctx->route_cap ? ctx->route_cap * 2 : 4;
                    struct sockaddr_in *tmp = realloc(ctx->routes_tmp, nc * sizeof(*tmp));
                    uint8_t *tmp2 = realloc(ctx->prefix_tmp, nc * sizeof(*tmp2));
                    if (!tmp || !tmp2) {
                        free(tmp); free(tmp2);
                        AD_LOG_TRANSPORT_ERROR("Out of memory while parsing routes for peer %s", ctx->current_peer.peer_id);
                        return 0; /* stop parsing */
                    }
                    ctx->routes_tmp = tmp;
                    ctx->prefix_tmp = tmp2;
                    ctx->route_cap = nc;
                }
                struct sockaddr_in addr;
                uint8_t preflen;
                if (parse_cidr(t, &addr, &preflen) == 0) {
                    ctx->routes_tmp[ctx->route_count] = addr;
                    ctx->prefix_tmp[ctx->route_count] = preflen;
                    ctx->route_count++;
                } else {
                    AD_LOG_TRANSPORT_WARN("Skipping invalid route '%s' for peer %s", t, ctx->current_peer.peer_id);
                }
                tok = strtok_r(NULL, ",", &save);
            }
        }
        else if (strcmp(name, "active") == 0) {
            ctx->current_peer.active = atoi(value) ? 1 : 0;
        }
        return 1;
    }

    /* unknown section -> ignore */
    return 1;
}

/* Commit the parser's current peer into the global table */
static ad_peer_table_error_t commit_current_peer(ini_peer_ctx_t *ctx)
{
    if (!ctx || !ctx->current_peer.peer_id) return AD_PEER_TABLE_OK;
    /* attach routes buffer to current_peer so add function can copy */
    ctx->current_peer.routes = ctx->routes_tmp;
    ctx->current_peer.route_prefixlen = ctx->prefix_tmp;
    ctx->current_peer.route_count = ctx->route_count;

    AD_LOG_TRANSPORT_INFO("Committing peer %s (routes=%zu) from INI", ctx->current_peer.peer_id, ctx->current_peer.route_count);

    ad_peer_table_error_t r = ad_transport_peer_table_add(&ctx->current_peer);
    if (r != AD_PEER_TABLE_OK) {
        AD_LOG_TRANSPORT_ERROR("Failed to add peer %s to table: %d", ctx->current_peer.peer_id, r);
    }

    /* free parser-owned buffers and reset only route buffers (ad_transport_peer_table_add copies them) */
    free(ctx->routes_tmp); ctx->routes_tmp = NULL;
    free(ctx->prefix_tmp); ctx->prefix_tmp = NULL;
    ctx->route_count = 0;
    ctx->route_cap = 0;

    /* free peer_id here, because add() duplicates it */
    free(ctx->current_peer.peer_id);
    ctx->current_peer.peer_id = NULL;
    ctx->current_peer.route_count = 0;
    return r;
}

/* ---------------------------
 * Public API
 * --------------------------- */

ad_transport_error_t ad_transport_peer_table_init_from_config(const char *config_path)
{
    if (!config_path) return AD_TRANSPORT_ERR_INVALID_ARGUMENT;

    if (!g_ad_global_peer_table) {
        g_ad_global_peer_table = calloc(1, sizeof(ad_transport_peer_table_t));
        if (!g_ad_global_peer_table) {
            AD_LOG_TRANSPORT_FATAL("No memory allocating global peer table");
            return AD_TRANSPORT_ERR_NO_MEMORY;
        }
        g_ad_global_peer_table->entries = calloc(DEFAULT_INITIAL_CAPACITY, sizeof(ad_transport_peer_t));
        if (!g_ad_global_peer_table->entries) {
            free(g_ad_global_peer_table);
            g_ad_global_peer_table = NULL;
            AD_LOG_TRANSPORT_FATAL("No memory allocating peer entries");
            return AD_TRANSPORT_ERR_NO_MEMORY;
        }
        g_ad_global_peer_table->capacity = DEFAULT_INITIAL_CAPACITY;
        pthread_mutex_init(&g_ad_global_peer_table->lock, NULL);
    }

    ini_peer_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.persist_interval_sec = DEFAULT_PERSIST_INTERVAL_SEC;

    int ini_ret = ini_parse(config_path, ad_transport_ini_handler, &ctx);
    if (ini_ret < 0) {
        AD_LOG_TRANSPORT_ERROR("Failed to parse config '%s' (ini_parse returned %d)", config_path, ini_ret);
        /* cleanup ctx */
        free(ctx.db_path);
        free(ctx.last_section);
        ini_ctx_reset_peer(&ctx, 1);
        return AD_TRANSPORT_ERR_CONFIG;
    }

    /* commit last pending peer */
    if (ctx.current_peer.peer_id) {
        commit_current_peer(&ctx);
    }

    /* copy config into global table */
    if (ctx.initial_capacity > 0) {
        /* grow global entries if initial capacity larger */
        if (ctx.initial_capacity > g_ad_global_peer_table->capacity) {
            ad_transport_peer_t *tmp = realloc(g_ad_global_peer_table->entries, ctx.initial_capacity * sizeof(ad_transport_peer_t));
            if (tmp) {
                g_ad_global_peer_table->entries = tmp;
                g_ad_global_peer_table->capacity = ctx.initial_capacity;
            }
        }
    }

    g_ad_global_peer_table->persist_interval_sec = ctx.persist_interval_sec;
    if (ctx.db_path) {
        free(g_ad_global_peer_table->db_path);
        g_ad_global_peer_table->db_path = strdup(ctx.db_path);
    }

    AD_LOG_TRANSPORT_INFO("Peer table initialized from config %s: capacity=%zu, persist_interval=%u, db=%s",
                         config_path,
                         g_ad_global_peer_table->capacity,
                         g_ad_global_peer_table->persist_interval_sec,
                         g_ad_global_peer_table->db_path ? g_ad_global_peer_table->db_path : "(none)");

    free(ctx.db_path);
    free(ctx.last_section);
    /* ctx routes already freed by commit_current_peer */

    return AD_TRANSPORT_OK;
}

/* Add a peer (makes deep copies) */
ad_peer_table_error_t ad_transport_peer_table_add(ad_transport_peer_t *peer)
{
    if (!peer || !g_ad_global_peer_table || !peer->peer_id) return AD_PEER_TABLE_ERR_INVALID_ARGUMENT;

    pthread_mutex_lock(&g_ad_global_peer_table->lock);

    /* check duplicate peer_id */
    for (size_t i = 0; i < g_ad_global_peer_table->count; i++) {
        if (g_ad_global_peer_table->entries[i].peer_id &&
            strcmp(g_ad_global_peer_table->entries[i].peer_id, peer->peer_id) == 0) {
            pthread_mutex_unlock(&g_ad_global_peer_table->lock);
            AD_LOG_TRANSPORT_WARN("Peer '%s' already exists", peer->peer_id);
            return AD_PEER_TABLE_ERR_EXISTS;
        }
    }

    /* grow if necessary */
    if (g_ad_global_peer_table->count >= g_ad_global_peer_table->capacity) {
        size_t newcap = g_ad_global_peer_table->capacity ? g_ad_global_peer_table->capacity * 2 : DEFAULT_INITIAL_CAPACITY;
        ad_transport_peer_t *tmp = realloc(g_ad_global_peer_table->entries, newcap * sizeof(ad_transport_peer_t));
        if (!tmp) {
            pthread_mutex_unlock(&g_ad_global_peer_table->lock);
            AD_LOG_TRANSPORT_ERROR("Out of memory while growing peer table");
            return AD_PEER_TABLE_ERR_NO_MEMORY;
        }
        /* zero the new area */
        memset(tmp + g_ad_global_peer_table->capacity, 0, (newcap - g_ad_global_peer_table->capacity) * sizeof(ad_transport_peer_t));
        g_ad_global_peer_table->entries = tmp;
        g_ad_global_peer_table->capacity = newcap;
    }

    /* copy peer */
    size_t idx = g_ad_global_peer_table->count++;
    ad_transport_peer_t *dst = &g_ad_global_peer_table->entries[idx];
    memset(dst, 0, sizeof(*dst));

    dst->peer_id = strdup(peer->peer_id);
    if (!dst->peer_id) {
        pthread_mutex_unlock(&g_ad_global_peer_table->lock);
        return AD_PEER_TABLE_ERR_NO_MEMORY;
    }
    dst->real_addr = peer->real_addr;
    dst->active = peer->active;

    dst->route_count = peer->route_count;
    if (dst->route_count > 0) {
        dst->routes = calloc(dst->route_count, sizeof(*dst->routes));
        dst->route_prefixlen = calloc(dst->route_count, sizeof(*dst->route_prefixlen));
        if (!dst->routes || !dst->route_prefixlen) {
            free(dst->peer_id);
            dst->peer_id = NULL;
            free(dst->routes); free(dst->route_prefixlen);
            dst->routes = NULL; dst->route_prefixlen = NULL;
            dst->route_count = 0;
            g_ad_global_peer_table->count--;
            pthread_mutex_unlock(&g_ad_global_peer_table->lock);
            return AD_PEER_TABLE_ERR_NO_MEMORY;
        }
        for (size_t i = 0; i < dst->route_count; i++) {
            dst->routes[i] = peer->routes[i];
            dst->route_prefixlen[i] = peer->route_prefixlen[i];
        }
    }

    pthread_mutex_unlock(&g_ad_global_peer_table->lock);
    AD_LOG_TRANSPORT_INFO("Added peer %s (routes=%zu) to table", dst->peer_id, dst->route_count);
    return AD_PEER_TABLE_OK;
}

/* Remove a peer by id */
ad_peer_table_error_t ad_transport_peer_table_remove(const char *peer_id)
{
    if (!peer_id || !g_ad_global_peer_table) return AD_PEER_TABLE_ERR_INVALID_ARGUMENT;

    pthread_mutex_lock(&g_ad_global_peer_table->lock);

    for (size_t i = 0; i < g_ad_global_peer_table->count; i++) {
        ad_transport_peer_t *peer = &g_ad_global_peer_table->entries[i];
        if (peer->peer_id && strcmp(peer->peer_id, peer_id) == 0) {
            AD_LOG_TRANSPORT_INFO("Removing peer %s", peer->peer_id);
            free(peer->peer_id);
            free(peer->routes);
            free(peer->route_prefixlen);

            /* shift remaining entries left to keep array compact */
            for (size_t j = i + 1; j < g_ad_global_peer_table->count; j++) {
                g_ad_global_peer_table->entries[j - 1] = g_ad_global_peer_table->entries[j];
            }
            /* zero last slot */
            memset(&g_ad_global_peer_table->entries[g_ad_global_peer_table->count - 1], 0, sizeof(ad_transport_peer_t));
            g_ad_global_peer_table->count--;
            pthread_mutex_unlock(&g_ad_global_peer_table->lock);
            return AD_PEER_TABLE_OK;
        }
    }
    pthread_mutex_unlock(&g_ad_global_peer_table->lock);
    return AD_PEER_TABLE_ERR_NOT_FOUND;
}

/* Lookup by IPv4 address LPM */
ad_transport_peer_t* ad_transport_peer_table_lookup(const struct sockaddr_in *addr)
{
    if (!addr || !g_ad_global_peer_table) {
        errno = EINVAL;
        return NULL;
    }

    pthread_mutex_lock(&g_ad_global_peer_table->lock);

    uint32_t ip = addr->sin_addr.s_addr;
    ad_transport_peer_t *best_peer = NULL;
    int best_prefix = -1;
    int conflict = 0;

    for (size_t i = 0; i < g_ad_global_peer_table->count; i++) {
        ad_transport_peer_t *peer = &g_ad_global_peer_table->entries[i];
        if (!peer->peer_id || !peer->routes) continue;
        const struct sockaddr_in *matched = NULL;
        uint8_t preflen = 0;
        int r = peer_match_lpm(peer, ip, &matched, &preflen);
        if (r == 1) {
            if ((int)preflen > best_prefix) { best_prefix = preflen; best_peer = peer; conflict = 0; }
            else if ((int)preflen == best_prefix) conflict = 1;
        } else if (r == -1) {
            conflict = 1;
        }
    }

    pthread_mutex_unlock(&g_ad_global_peer_table->lock);

    if (conflict) {
        /* multiple matches — set errno to EEXIST to indicate conflict (caller can interpret) */
        errno = EEXIST;
        return NULL;
    }
    if (!best_peer) {
        errno = ENOENT;
        return NULL;
    }

    return best_peer;
}

/* Cleanup */
ad_peer_table_error_t ad_transport_peer_table_cleanup(void)
{
    if (!g_ad_global_peer_table) return AD_PEER_TABLE_ERR_INTERNAL;

    pthread_mutex_lock(&g_ad_global_peer_table->lock);

    for (size_t i = 0; i < g_ad_global_peer_table->count; i++) {
        ad_transport_peer_t *peer = &g_ad_global_peer_table->entries[i];
        free(peer->peer_id);
        free(peer->routes);
        free(peer->route_prefixlen);
    }

    free(g_ad_global_peer_table->entries);
    pthread_mutex_unlock(&g_ad_global_peer_table->lock);
    pthread_mutex_destroy(&g_ad_global_peer_table->lock);
    free(g_ad_global_peer_table);
    g_ad_global_peer_table = NULL;
    AD_LOG_TRANSPORT_INFO("Peer table cleaned up");
    return AD_PEER_TABLE_OK;
}

ad_transport_peer_table_t* ad_get_global_peer_table(void)
{
    return g_ad_global_peer_table;
}

ad_transport_peer_table_t ad_get_global_peer_table_copy(void)
{
    ad_transport_peer_table_t copy;
    memset(&copy, 0, sizeof(copy));
    if (!g_ad_global_peer_table) return copy;

    pthread_mutex_lock(&g_ad_global_peer_table->lock);
    copy.entries = g_ad_global_peer_table->entries;
    copy.count = g_ad_global_peer_table->count;
    copy.capacity = g_ad_global_peer_table->capacity;
    copy.persist_interval_sec = g_ad_global_peer_table->persist_interval_sec;
    copy.db_path = g_ad_global_peer_table->db_path;
    pthread_mutex_unlock(&g_ad_global_peer_table->lock);

    return copy;
}

/* DB open: sets up tables */
ad_peer_table_error_t ad_peer_table_db_open(const char *path)
{
    if (!path) return AD_PEER_TABLE_ERR_INVALID_ARGUMENT;

    if (sqlite3_open(path, &g_db) != SQLITE_OK) {
        AD_LOG_TRANSPORT_ERROR("Failed to open sqlite DB %s", path);
        return AD_PEER_TABLE_ERR_DB_OPEN;
    }

    const char *sql =
        "CREATE TABLE IF NOT EXISTS peers ("
        "  id TEXT PRIMARY KEY,"
        "  real_ip TEXT NOT NULL,"
        "  real_port INTEGER NOT NULL,"
        "  active INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS peer_routes ("
        "  peer_id TEXT NOT NULL,"
        "  cidr TEXT NOT NULL,"
        "  prefix INTEGER NOT NULL,"
        "  FOREIGN KEY(peer_id) REFERENCES peers(id)"
        ");";

    char *err = NULL;
    if (sqlite3_exec(g_db, sql, NULL, NULL, &err) != SQLITE_OK) {
        AD_LOG_TRANSPORT_ERROR("DB schema creation failed: %s", err ? err : "(null)");
        sqlite3_free(err);
        sqlite3_close(g_db);
        g_db = NULL;
        return AD_PEER_TABLE_ERR_DB_WRITE;
    }

    AD_LOG_TRANSPORT_INFO("Opened DB %s", path);
    return AD_PEER_TABLE_OK;
}

/* DB load: loads peers and their routes */
ad_peer_table_error_t ad_peer_table_db_load(void)
{
    if (!g_db || !g_ad_global_peer_table) return AD_PEER_TABLE_ERR_INTERNAL;

    sqlite3_stmt *s1 = NULL, *s2 = NULL;
    const char *sql_peers = "SELECT id, real_ip, real_port, active FROM peers;";
    if (sqlite3_prepare_v2(g_db, sql_peers, -1, &s1, NULL) != SQLITE_OK) {
        AD_LOG_TRANSPORT_ERROR("Failed to prepare peers select");
        return AD_PEER_TABLE_ERR_DB_QUERY;
    }

    /* clear current table before load */
    pthread_mutex_lock(&g_ad_global_peer_table->lock);
    for (size_t i = 0; i < g_ad_global_peer_table->count; i++) {
        free(g_ad_global_peer_table->entries[i].peer_id);
        free(g_ad_global_peer_table->entries[i].routes);
        free(g_ad_global_peer_table->entries[i].route_prefixlen);
    }
    g_ad_global_peer_table->count = 0;
    pthread_mutex_unlock(&g_ad_global_peer_table->lock);

    while (sqlite3_step(s1) == SQLITE_ROW) {
        ad_transport_peer_t peer;
        memset(&peer, 0, sizeof(peer));

        const unsigned char *idtxt = sqlite3_column_text(s1, 0);
        const unsigned char *rip = sqlite3_column_text(s1, 1);
        int rport = sqlite3_column_int(s1, 2);
        int active = sqlite3_column_int(s1, 3);

        if (!idtxt || !rip) continue;
        peer.peer_id = strdup((const char*)idtxt);
        peer.active = active;
        peer.real_addr.sin_family = AF_INET;
        inet_pton(AF_INET, (const char*)rip, &peer.real_addr.sin_addr);
        peer.real_addr.sin_port = htons(rport);

        /* load routes for this peer */
        if (sqlite3_prepare_v2(g_db, "SELECT cidr, prefix FROM peer_routes WHERE peer_id=?;", -1, &s2, NULL) == SQLITE_OK) {
            sqlite3_bind_text(s2, 1, (const char*)idtxt, -1, SQLITE_STATIC);
            while (sqlite3_step(s2) == SQLITE_ROW) {
                const unsigned char *cidr = sqlite3_column_text(s2, 0);
                int prefix = sqlite3_column_int(s2, 1);
                if (cidr) {
                    struct sockaddr_in addr;
                    uint8_t pref = (uint8_t)prefix;
                    if (parse_cidr((const char*)cidr, &addr, &pref) == 0) {
                        add_route_to_peer(&peer, addr, pref);
                    } else {
                        AD_LOG_TRANSPORT_WARN("Skipping invalid CIDR '%s' while loading DB", cidr);
                    }
                }
            }
            sqlite3_finalize(s2);
            s2 = NULL;
        }

        /* add peer into table (ad_transport will copy) */
        ad_peer_table_error_t ar = ad_transport_peer_table_add(&peer);
        if (ar != AD_PEER_TABLE_OK) {
            AD_LOG_TRANSPORT_ERROR("Failed to add peer %s from DB: %d", peer.peer_id ? peer.peer_id : "(null)", ar);
        }
        /* free peer temporary allocations created by add_route_to_peer */
        free(peer.peer_id);
        free(peer.routes);
        free(peer.route_prefixlen);
    }

    sqlite3_finalize(s1);
    AD_LOG_TRANSPORT_INFO("Loaded peers from DB");
    return AD_PEER_TABLE_OK;
}

/* DB save: truncates and writes entire table */
ad_peer_table_error_t ad_peer_table_db_save(void)
{
    if (!g_db || !g_ad_global_peer_table) return AD_PEER_TABLE_ERR_INTERNAL;

    char *err = NULL;
    pthread_mutex_lock(&g_ad_global_peer_table->lock);

    if (sqlite3_exec(g_db, "BEGIN;", NULL, NULL, &err) != SQLITE_OK) {
        AD_LOG_TRANSPORT_ERROR("DB begin failed: %s", err ? err : "(null)");
        sqlite3_free(err); err = NULL;
        pthread_mutex_unlock(&g_ad_global_peer_table->lock);
        return AD_PEER_TABLE_ERR_DB_WRITE;
    }
    sqlite3_exec(g_db, "DELETE FROM peer_routes;", NULL, NULL, NULL);
    sqlite3_exec(g_db, "DELETE FROM peers;", NULL, NULL, NULL);

    for (size_t i = 0; i < g_ad_global_peer_table->count; i++) {
        ad_transport_peer_t *p = &g_ad_global_peer_table->entries[i];
        char ipbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &p->real_addr.sin_addr, ipbuf, sizeof(ipbuf));
        int port = ntohs(p->real_addr.sin_port);

        /* Insert peer */
        sqlite3_stmt *ins1 = NULL;
        if (sqlite3_prepare_v2(g_db, "INSERT INTO peers (id, real_ip, real_port, active) VALUES (?, ?, ?, ?);", -1, &ins1, NULL) == SQLITE_OK) {
            sqlite3_bind_text(ins1, 1, p->peer_id, -1, SQLITE_STATIC);
            sqlite3_bind_text(ins1, 2, ipbuf, -1, SQLITE_STATIC);
            sqlite3_bind_int(ins1, 3, port);
            sqlite3_bind_int(ins1, 4, p->active);
            sqlite3_step(ins1);
            sqlite3_finalize(ins1);
        }

        /* insert routes */
        for (size_t r = 0; r < p->route_count; r++) {
            char cidrbuf[64];
            make_cidr_string(&p->routes[r], p->route_prefixlen[r], cidrbuf, sizeof(cidrbuf));
            sqlite3_stmt *ins2 = NULL;
            if (sqlite3_prepare_v2(g_db, "INSERT INTO peer_routes (peer_id, cidr, prefix) VALUES (?, ?, ?);", -1, &ins2, NULL) == SQLITE_OK) {
                sqlite3_bind_text(ins2, 1, p->peer_id, -1, SQLITE_STATIC);
                sqlite3_bind_text(ins2, 2, cidrbuf, -1, SQLITE_STATIC);
                sqlite3_bind_int(ins2, 3, p->route_prefixlen[r]);
                sqlite3_step(ins2);
                sqlite3_finalize(ins2);
            }
        }
    }

    if (sqlite3_exec(g_db, "COMMIT;", NULL, NULL, &err) != SQLITE_OK) {
        AD_LOG_TRANSPORT_ERROR("DB commit failed: %s", err ? err : "(null)");
        sqlite3_free(err);
        pthread_mutex_unlock(&g_ad_global_peer_table->lock);
        return AD_PEER_TABLE_ERR_DB_WRITE;
    }

    pthread_mutex_unlock(&g_ad_global_peer_table->lock);
    AD_LOG_TRANSPORT_DEBUG("Saved peers to DB");
    return AD_PEER_TABLE_OK;
}

/* Persistence thread */
static void* persist_thread_fn(void *arg)
{
    AD_LOG_TRANSPORT_INFO("Peer-table persistence thread started");
    while (g_run_persist) {
        sleep(g_ad_global_peer_table ? g_ad_global_peer_table->persist_interval_sec : DEFAULT_PERSIST_INTERVAL_SEC);
        if (!g_run_persist) break;
        if (g_db) {
            ad_peer_table_db_save();
        }
    }
    AD_LOG_TRANSPORT_INFO("Peer-table persistence thread exiting");
    return NULL;
}

ad_peer_table_error_t ad_peer_table_start_persistence(void)
{
    if (!g_ad_global_peer_table) return AD_PEER_TABLE_ERR_INTERNAL;
    if (g_run_persist) return AD_PEER_TABLE_OK; /* already running */
    g_run_persist = 1;
    int r = pthread_create(&g_persist_thread, NULL, persist_thread_fn, NULL);
    if (r != 0) {
        AD_LOG_TRANSPORT_ERROR("Failed to start persist thread: %d", r);
        g_run_persist = 0;
        return AD_PEER_TABLE_ERR_INTERNAL;
    }
    return AD_PEER_TABLE_OK;
}

ad_peer_table_error_t ad_peer_table_stop_persistence(void)
{
    if (!g_run_persist) return AD_PEER_TABLE_OK;
    g_run_persist = 0;
    if (g_persist_thread) {
        pthread_join(g_persist_thread, NULL);
        g_persist_thread = 0;
    }
    return AD_PEER_TABLE_OK;
}

ad_peer_table_error_t ad_peer_table_db_close(void)
{
    /* Stop persistence thread first */
    ad_peer_table_stop_persistence();

    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }
    AD_LOG_TRANSPORT_INFO("Closed DB");
    return AD_PEER_TABLE_OK;
}

/* Map peer-table errors to transport-level errors */
ad_transport_error_t ad_transport_map_peer_table_error(ad_peer_table_error_t e) {
    switch (e) {
        case AD_PEER_TABLE_ERR_NOT_FOUND:
            return AD_TRANSPORT_ERR_NOT_FOUND;
        case AD_PEER_TABLE_ERR_EXISTS:
            return AD_TRANSPORT_ERR_EXISTS;
        case AD_PEER_TABLE_ERR_NO_MEMORY:
            return AD_TRANSPORT_ERR_NO_MEMORY;
        case AD_PEER_TABLE_OK:
            return AD_TRANSPORT_OK;
        default:
            return AD_TRANSPORT_ERR_PEER_TABLE;
    }
}
