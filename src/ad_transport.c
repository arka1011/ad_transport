/*************************************************
**************************************************
**          Name: AD Transport Implementation   **
**          Author: Arkaprava Das               **
**************************************************
**************************************************/

#include "../include/ad_transport.h"
#include "../../ad_tun/include/ad_tun.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>     /* sleep */
#include <ctype.h>      /* isspace */
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>


/* ============================
 * Logging Macros are expected
 * to be visible via ad_logger include
 * Use your AD_LOG_TRANSPORT_* macros
 * ============================ */

/* Default port */
static const int port = 6000; // Set your desired VPN port here

/* Global definitions */
/* Global transport config (single definition) */
ad_transport_config_t g_transport_config = {0};

/* Server address for traffic forwarding (set from config) */
static struct sockaddr_in g_server_addr = {0};

/* ---------------------------
 * Config helpers
 * --------------------------- */

/* ========================= 
 * Config parsing helpers
 * ========================= */

/* ========================= 
 * Simple server config parsing
 * ========================= */

/* Context for INI parsing */
typedef struct {
    int found;
    struct sockaddr_in *server_addr;
} config_parse_ctx_t;

/* INI handler for server config */
static int config_ini_handler(void *user, const char *section, const char *name, const char *value)
{
    config_parse_ctx_t *ctx = (config_parse_ctx_t *)user;
    if (!ctx || !section || !name) return 0;

    if (strcmp(section, "ad_transport") == 0 && strcmp(name, "server_addr") == 0) {
        /* Parse server_addr in format "IP:PORT" */
        char buf[64];
        strncpy(buf, value, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        char *colon = strrchr(buf, ':');
        if (!colon) {
            AD_LOG_TRANSPORT_ERROR("Invalid server_addr format. Expected 'IP:PORT', got: %s", value);
            return 0;
        }

        *colon = '\0';
        const char *ip_str = buf;
        const char *port_str = colon + 1;

        int port = atoi(port_str);
        if (port <= 0 || port > 65535) {
            AD_LOG_TRANSPORT_ERROR("Invalid port number: %s", port_str);
            return 0;
        }

        /* Set up server address */
        memset(ctx->server_addr, 0, sizeof(*ctx->server_addr));
        ctx->server_addr->sin_family = AF_INET;
        ctx->server_addr->sin_port = htons((uint16_t)port);

        if (inet_pton(AF_INET, ip_str, &ctx->server_addr->sin_addr) != 1) {
            AD_LOG_TRANSPORT_ERROR("Invalid IP address: %s", ip_str);
            return 0;
        }

        ctx->found = 1;
        AD_LOG_TRANSPORT_INFO("Loaded server config: %s:%d", ip_str, port);
        return 1;
    }

    return 1;
}

/* Parse server address from config file */
static ad_transport_error_t ad_transport_load_server_config(const char *config_path)
{
    if (!config_path) return AD_TRANSPORT_ERR_INVALID_ARGUMENT;

    config_parse_ctx_t ctx = {0};
    ctx.server_addr = &g_server_addr;

    int ini_ret = ini_parse(config_path, config_ini_handler, &ctx);
    if (ini_ret < 0) {
        AD_LOG_TRANSPORT_ERROR("Failed to parse config file: %s (ini_parse returned %d)", config_path, ini_ret);
        return AD_TRANSPORT_ERR_CONFIG;
    }

    if (!ctx.found) {
        AD_LOG_TRANSPORT_ERROR("Missing 'server_addr' in config file");
        return AD_TRANSPORT_ERR_CONFIG;
    }

    return AD_TRANSPORT_OK;
}

/* =========================================================
 * Internal state
 * ========================================================= */

static ad_transport_state_t g_state = AD_TRANSPORT_STATE_STOPPED;
static ad_transport_stats_t g_stats;
static int g_udp_fd = -1;

/* =========================================================
 * Helpers
 * ========================================================= */

static ad_transport_error_t
map_errno_to_transport(void)
{
    switch (errno) {
        case EINVAL: return AD_TRANSPORT_ERR_INVALID_ARGUMENT;
        case ENOMEM: return AD_TRANSPORT_ERR_NO_MEMORY;
        default:     return AD_TRANSPORT_ERR_IO;
    }
}

static void
stats_reset(void)
{
    memset(&g_stats, 0, sizeof(g_stats));
}

/* =========================================================
 * Lifecycle
 * ========================================================= */

ad_transport_error_t
ad_transport_init_with_config(const ad_transport_config_t *cfg)
{
    if (!cfg || !cfg->config_path)
        return AD_TRANSPORT_ERR_INVALID_ARGUMENT;

    if (g_state != AD_TRANSPORT_STATE_STOPPED)
        return AD_TRANSPORT_ERR_INVALID_ARGUMENT;

    memset(&g_transport_config, 0, sizeof(g_transport_config));
    g_transport_config.config_path = strdup(cfg->config_path);

    stats_reset();

    /* Load server configuration from INI file */
    ad_transport_error_t te = ad_transport_load_server_config(cfg->config_path);
    if (te != AD_TRANSPORT_OK)
        return te;

    /* Init TUN (delegated) */
    ad_tun_config_t tun_cfg;
    if (ad_tun_load_config(cfg->config_path, &tun_cfg) != AD_TUN_OK)
        return AD_TRANSPORT_ERR_CONFIG;

    if (ad_tun_init(&tun_cfg) != AD_TUN_OK)
        return AD_TRANSPORT_ERR_INTERNAL;

    ad_tun_free_config(&tun_cfg);

    g_state = AD_TRANSPORT_STATE_STOPPED;
    return AD_TRANSPORT_OK;
}

ad_transport_error_t
ad_transport_start(void)
{
    if (g_state != AD_TRANSPORT_STATE_STOPPED)
        return AD_TRANSPORT_ERR_INVALID_ARGUMENT;

    /* UDP socket */
    g_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_udp_fd < 0)
        return map_errno_to_transport();

    fcntl(g_udp_fd, F_SETFL, O_NONBLOCK);

    /* Bind UDP socket to a specific port */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    addr.sin_port = htons(port);

    if (bind(g_udp_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(g_udp_fd);
        return AD_TRANSPORT_ERR_INTERNAL;
    }

    /* Start TUN */
    if (ad_tun_start() != AD_TUN_OK)
        return AD_TRANSPORT_ERR_INTERNAL;

    g_state = AD_TRANSPORT_STATE_RUNNING;
    return AD_TRANSPORT_OK;
}


ad_transport_error_t
ad_transport_stop(void)
{
    if (g_state != AD_TRANSPORT_STATE_RUNNING)
        return AD_TRANSPORT_ERR_INVALID_ARGUMENT;

    ad_tun_stop();
    ad_tun_cleanup();

    if (g_udp_fd >= 0) {
        close(g_udp_fd);
        g_udp_fd = -1;
    }

    g_state = AD_TRANSPORT_STATE_STOPPED;
    return AD_TRANSPORT_OK;
}

ad_transport_error_t
ad_transport_stop_graceful(unsigned int timeout_ms)
{
    (void)timeout_ms; /* currently synchronous */
    return ad_transport_stop();
}

ad_transport_error_t
ad_transport_restart(void)
{
    ad_transport_stop();
    return ad_transport_start();
}

ad_transport_state_t
ad_transport_get_state(void)
{
    return g_state;
}

/* =========================================================
 * FD access
 * ========================================================= */

ad_transport_error_t
ad_transport_get_udp_fd(int *out_fd)
{
    if (!out_fd || g_udp_fd < 0)
        return AD_TRANSPORT_ERR_INVALID_ARGUMENT;

    *out_fd = g_udp_fd;
    return AD_TRANSPORT_OK;
}

ad_transport_error_t
ad_transport_get_tun_fd(int *out_fd)
{
    if (!out_fd)
        return AD_TRANSPORT_ERR_INVALID_ARGUMENT;

    int fd = ad_tun_get_fd();
    if (fd < 0)
        return AD_TRANSPORT_ERR_INTERNAL;

    *out_fd = fd;
    return AD_TRANSPORT_OK;
}

/* =========================================================
 * Message helpers
 * ========================================================= */

ad_transport_error_t
ad_transport_pack_header(uint8_t *buf, size_t buf_len,
                         uint8_t msg_type, uint16_t msg_len)
{
    if (!buf || buf_len < 3)
        return AD_TRANSPORT_ERR_INVALID_ARGUMENT;

    buf[0] = msg_type;
    buf[1] = (msg_len >> 8) & 0xff;
    buf[2] = msg_len & 0xff;
    return AD_TRANSPORT_OK;
}

ad_transport_error_t
ad_transport_unpack_header(const uint8_t *buf, size_t buf_len,
                           uint8_t *msg_type, uint16_t *msg_len)
{
    if (!buf || buf_len < 3 || !msg_type || !msg_len)
        return AD_TRANSPORT_ERR_INVALID_ARGUMENT;

    *msg_type = buf[0];
    *msg_len  = ((uint16_t)buf[1] << 8) | buf[2];
    return AD_TRANSPORT_OK;
}

/* =========================================================
 * Encryption (stubbed cleanly)
 * ========================================================= */

ad_transport_error_t
ad_transport_encrypt_message(const uint8_t *pt, size_t pt_len,
                             uint8_t **ct, size_t *ct_len)
{
    if (!pt || !ct || !ct_len)
        return AD_TRANSPORT_ERR_INVALID_ARGUMENT;

    *ct = malloc(pt_len);
    if (!*ct)
        return AD_TRANSPORT_ERR_NO_MEMORY;

    memcpy(*ct, pt, pt_len);
    *ct_len = pt_len;
    return AD_TRANSPORT_OK;
}

ad_transport_error_t
ad_transport_decrypt_message(const uint8_t *ct, size_t ct_len,
                             uint8_t **pt, size_t *pt_len)
{
    return ad_transport_encrypt_message(ct, ct_len, pt, pt_len);
}

void
ad_transport_free_message(uint8_t *buf)
{
    free(buf);
}

/* =========================================================
 * UDP I/O
 * ========================================================= */

ad_transport_error_t
ad_transport_read_udp_message(int fd, uint8_t **out_buf, uint16_t *out_len)
{
    if (!out_buf || !out_len)
        return AD_TRANSPORT_ERR_INVALID_ARGUMENT;

    uint8_t *buf = malloc(2048);
    if (!buf)
        return AD_TRANSPORT_ERR_NO_MEMORY;

    ssize_t r = recv(fd, buf, 2048, 0);
    if (r <= 0) {
        free(buf);
        return AD_TRANSPORT_ERR_IO;
    }

    *out_buf = buf;
    *out_len = (uint16_t)r;
    g_stats.udp_rx++;
    return AD_TRANSPORT_OK;
}

ad_transport_error_t
ad_transport_write_udp_message(
    int fd,
    const uint8_t *buf,
    uint16_t len,
    const struct sockaddr_in *peer_addr)
{
    if (!buf || !peer_addr || len == 0)
        return AD_TRANSPORT_ERR_INVALID_ARGUMENT;

    AD_LOG_TRANSPORT_DEBUG(
            "Sending UDP message of %u bytes to %s:%u",
            len,
            inet_ntoa(peer_addr->sin_addr),
            ntohs(peer_addr->sin_port));

    ssize_t w = sendto(fd, buf, len, 0, (const struct sockaddr *)peer_addr, sizeof(*peer_addr));

    if (w < 0) {
        AD_LOG_TRANSPORT_ERROR(
            "UDP sendto failed (errno=%d: %s)",
            errno, strerror(errno));
        return AD_TRANSPORT_ERR_IO;
    }

    if (w != len) {
        AD_LOG_TRANSPORT_ERROR(
            "UDP partial send (%zd/%u bytes)", w, len);
        return AD_TRANSPORT_ERR_IO;
    }

    g_stats.udp_tx++;
    return AD_TRANSPORT_OK;
}

/* =========================================================
 * TUN I/O
 * ========================================================= */

ad_transport_error_t
ad_transport_read_tun_message(char *buf, size_t buf_len, ssize_t *out_len)
{
    ssize_t r = ad_tun_read(buf, buf_len);
    if (r < 0)
        return AD_TRANSPORT_ERR_IO;

    *out_len = r;
    g_stats.tun_rx++;
    return AD_TRANSPORT_OK;
}

ad_transport_error_t
ad_transport_write_tun_message(const char *buf, size_t buf_len, ssize_t *out_len)
{
    ssize_t w = ad_tun_write(buf, buf_len);
    if (w < 0)
        return AD_TRANSPORT_ERR_IO;

    *out_len = w;
    g_stats.tun_tx++;
    return AD_TRANSPORT_OK;
}

/* =========================================================
 * Event handlers
 * ========================================================= */

/* Helper function to calculate IPv4 header checksum */
static uint16_t compute_ip_checksum(const uint8_t *buf, size_t len)
{
    uint32_t sum = 0;
    const uint16_t *words = (const uint16_t *)buf;

    /* Sum all 16-bit words */
    for (size_t i = 0; i < len / 2; i++) {
        sum += ntohs(words[i]);
    }

    /* Handle odd byte if present */
    if (len % 2) {
        sum += ((uint8_t *)buf)[len - 1] << 8;
    }

    /* Fold 32-bit sum into 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return htons(~sum);
}

ad_transport_error_t
ad_transport_handle_tun_event(void)
{
    uint8_t buf[2048];
    ssize_t len;

    if (ad_transport_read_tun_message((char *)buf, sizeof(buf), &len) != AD_TRANSPORT_OK)
        return AD_TRANSPORT_ERR_IO;

    /* Interpret buffer as IPv4 header */
    struct iphdr *ip = (struct iphdr *)buf;

    /* Sanity check */
    if (ip->version != 4) {
        AD_LOG_TUN_DEBUG("Non-IPv4 packet received, dropping");
        return AD_TRANSPORT_ERR_NOT_FOUND;
    }

    /* Set source address to TUN interface IP */
    const char *tun_ipv4 = ad_tun_get_ipv4();
    if (tun_ipv4) {
        /* Extract IP from CIDR notation (e.g., "10.10.0.2/24" -> "10.10.0.2") */
        char ip_str[INET_ADDRSTRLEN];
        strncpy(ip_str, tun_ipv4, sizeof(ip_str) - 1);
        ip_str[sizeof(ip_str) - 1] = '\0';
        
        char *slash = strchr(ip_str, '/');
        if (slash) *slash = '\0';
        
        struct in_addr src_addr_struct;
        if (inet_pton(AF_INET, ip_str, &src_addr_struct) == 1) {
            ip->saddr = src_addr_struct.s_addr;
            
            /* Recalculate IP checksum (set checksum field to 0 first) */
            ip->check = 0;
            ip->check = compute_ip_checksum((const uint8_t *)ip, ip->ihl * 4);
            
            AD_LOG_TRANSPORT_DEBUG("Set source address to %s", ip_str);
        } else {
            AD_LOG_TRANSPORT_WARN("Failed to parse TUN interface IP: %s", tun_ipv4);
        }
    } else {
        AD_LOG_TRANSPORT_WARN("Failed to get TUN interface IP address");
    }

    /* Forward all traffic to the configured server */
    if (g_server_addr.sin_addr.s_addr == 0) {
        AD_LOG_TUN_ERROR("Server address not configured");
        g_stats.dropped_packets++;
        return AD_TRANSPORT_ERR_NOT_FOUND;
    }

    AD_LOG_TRANSPORT_DEBUG("Forwarding packet to server %s:%u",
                           inet_ntoa(g_server_addr.sin_addr),
                           ntohs(g_server_addr.sin_port));

    return ad_transport_write_udp_message(
        g_udp_fd, buf, (uint16_t)len, &g_server_addr);
}


ad_transport_error_t
ad_transport_handle_udp_event(void)
{
    uint8_t *buf = NULL;
    uint16_t len = 0;

    if (ad_transport_read_udp_message(g_udp_fd, &buf, &len)
        != AD_TRANSPORT_OK) {
        return AD_TRANSPORT_ERR_IO;
    }

    if (len < sizeof(struct iphdr)) {
        AD_LOG_TRANSPORT_ERROR("UDP packet too small (%u bytes)", len);
        ad_transport_free_message(buf);
        return AD_TRANSPORT_ERR_INTERNAL;
    }

    struct iphdr *ip = (struct iphdr *)buf;

    if (ip->version != 4) {
        AD_LOG_GENERAL_ERROR("Non-IPv4 packet received over UDP");
        ad_transport_free_message(buf);
        return AD_TRANSPORT_ERR_INTERNAL;
    }

    //AD_LOG_TRANSPORT_DEBUG("ad_tun_get_fd(): %d", ad_tun_get_fd());
    ssize_t w = write(ad_tun_get_fd(), buf, len);
    if (w != len) {
        AD_LOG_TRANSPORT_ERROR("Failed to write UDP packet to TUN");
        ad_transport_free_message(buf);
        return AD_TRANSPORT_ERR_IO;
    }

    AD_LOG_TRANSPORT_DEBUG(
        "Injected %u bytes into TUN (dst=%s)",
        len,
        inet_ntoa(*(struct in_addr *)&ip->daddr));

    ad_transport_free_message(buf);
    return AD_TRANSPORT_OK;
}

/* =========================================================
 * Stats
 * ========================================================= */

ad_transport_error_t
ad_transport_get_stats(ad_transport_stats_t *out)
{
    if (!out)
        return AD_TRANSPORT_ERR_INVALID_ARGUMENT;

    *out = g_stats;
    return AD_TRANSPORT_OK;
}

