#include "../../../prebuilt/googletest/googletest/include/gtest/gtest.h"
#include <arpa/inet.h>
#include <fstream>
#include <unistd.h>
#include <vector>
#include <string>

extern "C" {
#include "../include/ad_transport.h"
}

/* ---------------------------------------------
 * Helper: temporary INI
 * --------------------------------------------- */
static std::string write_temp_ini() {
    std::string path = "/tmp/ad_transport_test.ini";
    std::ofstream f(path);
    f <<
    "[peer_table]\n"
    "capacity = 4\n"
    "persist_interval = 5\n"
    "db_path = /tmp/ad_transport_test.db\n"
    "\n"
    "[peer:peer1]\n"
    "real_addr = 10.0.0.1:5555\n"
    "routes = 192.168.1.0/24,10.10.0.0/16\n"
    "active = 1\n"
    "\n"
    "[peer:peer2]\n"
    "real_addr = 172.16.1.1:8080\n"
    "routes = 172.16.0.0/16\n"
    "active = 0\n";
    return path;
}

static std::string write_temp_ini_2() {
    std::string path = "/tmp/ad_transport_test.ini";
    std::ofstream f(path);
    f <<
    "[peer_table]\n"
    "capacity = 4\n"
    "persist_interval = 5\n"
    "db_path = /tmp/ad_transport_test.db\n"
    "\n"
    "[peer:peer1]\n"
    "real_addr = 10.0.0.1:5555\n"
    "routes = 192.168.1.0/24,10.10.0.0/16\n"
    "active = 1\n"
    "\n"
    "[peer:peer2]\n"
    "real_addr = 172.16.1.1:8080\n"
    "routes = 172.16.0.0/16,10.10.0.0/16\n"
    "active = 0\n";
    return path;
}

/* ---------------------------------------------
 * Fixture
 * --------------------------------------------- */
class TransportTest : public ::testing::Test {
protected:
    void TearDown() override {
        ad_transport_peer_table_cleanup();
        ad_transport_peer_table_db_close();
        unlink("/tmp/ad_transport_test.db");
    }
};

/* ---------------------------------------------
 * Init from config
 * --------------------------------------------- */
TEST_F(TransportTest, InitFromConfig) {
    EXPECT_EQ(ad_transport_peer_table_init_from_config(write_temp_ini().c_str()),
              AD_TRANSPORT_OK);

    auto *t = ad_transport_get_global_peer_table();
    ASSERT_NE(t, nullptr);
    EXPECT_EQ(t->count, 2u);
    EXPECT_EQ(t->persist_interval_sec, 5u);
}

/* ---------------------------------------------
 * Add Peer
 * --------------------------------------------- */
TEST_F(TransportTest, AddPeer) {
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());

    ad_transport_peer_t p{};
    p.peer_id = strdup("peer3");
    p.active = 1;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "100.64.0.0", &addr.sin_addr);

    p.route_count = 1;
    p.routes = (sockaddr_in*)calloc(1, sizeof(sockaddr_in));
    p.route_prefixlen = (uint8_t*)calloc(1, sizeof(uint8_t));
    p.routes[0] = addr;
    p.route_prefixlen[0] = 10;

    EXPECT_EQ(ad_transport_peer_table_add(&p), AD_PEER_TABLE_OK);
    EXPECT_EQ(ad_transport_get_global_peer_table()->count, 3u);

    free(p.peer_id);
    free(p.routes);
    free(p.route_prefixlen);
}

/* ---------------------------------------------
 * Update Peer
 * --------------------------------------------- */
TEST_F(TransportTest, UpdatePeer) {
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());

    ad_transport_peer_t upd{};
    upd.peer_id = strdup("peer1");
    upd.active = 0;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.100.0", &addr.sin_addr);

    upd.route_count = 1;
    upd.routes = (sockaddr_in*)calloc(1, sizeof(sockaddr_in));
    upd.route_prefixlen = (uint8_t*)calloc(1, sizeof(uint8_t));
    upd.routes[0] = addr;
    upd.route_prefixlen[0] = 24;

    EXPECT_EQ(ad_transport_peer_table_update(&upd), AD_PEER_TABLE_OK);

    sockaddr_in q{};
    q.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.100.5", &q.sin_addr);

    auto *p = ad_transport_peer_table_lookup(&q);
    ASSERT_NE(p, nullptr);
    EXPECT_STREQ(p->peer_id, "peer1");
    EXPECT_EQ(p->active, 0);

    free(upd.peer_id);
    free(upd.routes);
    free(upd.route_prefixlen);
}

/* ---------------------------------------------
 * Set Active / Inactive
 * --------------------------------------------- */
TEST_F(TransportTest, SetPeerActive) {
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());

    EXPECT_EQ(ad_transport_peer_table_set_active("peer2", 1),
              AD_PEER_TABLE_OK);

    sockaddr_in q{};
    q.sin_family = AF_INET;
    inet_pton(AF_INET, "172.16.10.1", &q.sin_addr);

    auto *p = ad_transport_peer_table_lookup(&q);
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->active, 1);
}

/* ---------------------------------------------
 * Lookup – LPM conflict
 * --------------------------------------------- */
TEST_F(TransportTest, LookupConflict) {
    ad_transport_peer_table_init_from_config(write_temp_ini_2().c_str());

    sockaddr_in q{};
    q.sin_family = AF_INET;
    inet_pton(AF_INET, "10.10.5.5", &q.sin_addr); // overlaps /16

    errno = 0;
    auto *p = ad_transport_peer_table_lookup(&q);
    EXPECT_EQ(p, nullptr);
    EXPECT_EQ(errno, EEXIST);
}

/* ---------------------------------------------
 * Foreach
 * --------------------------------------------- */
static int collect_ids(const ad_transport_peer_t *p, void *user) {
    auto *v = static_cast<std::vector<std::string>*>(user);
    v->push_back(p->peer_id);
    return 0;
}

TEST_F(TransportTest, ForeachPeers) {
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());

    std::vector<std::string> ids;
    EXPECT_EQ(ad_transport_peer_table_foreach(collect_ids, &ids),
              AD_PEER_TABLE_OK);

    EXPECT_EQ(ids.size(), 2u);
    EXPECT_NE(std::find(ids.begin(), ids.end(), "peer1"), ids.end());
    EXPECT_NE(std::find(ids.begin(), ids.end(), "peer2"), ids.end());
}

/* ---------------------------------------------
 * DB Save + Reload
 * --------------------------------------------- */
TEST_F(TransportTest, DBSaveReload) {
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());
    EXPECT_EQ(ad_transport_peer_table_db_open("/tmp/ad_transport_test.db"),
              AD_PEER_TABLE_OK);

    EXPECT_EQ(ad_transport_peer_table_db_save(), AD_PEER_TABLE_OK);

    /* wipe table */
    ad_transport_peer_table_cleanup();
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());

    EXPECT_EQ(ad_transport_peer_table_db_load(), AD_PEER_TABLE_OK);

    auto *t = ad_transport_get_global_peer_table();
    ASSERT_NE(t, nullptr);
    EXPECT_EQ(t->count, 2u);
}

/* ---------------------------------------------
 * Remove
 * --------------------------------------------- */
TEST_F(TransportTest, RemovePeer) {
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());
    EXPECT_EQ(ad_transport_peer_table_remove("peer1"), AD_PEER_TABLE_OK);
    EXPECT_EQ(ad_transport_get_global_peer_table()->count, 1u);
}

/* ---------------------------------------------
 * Cleanup
 * --------------------------------------------- */
TEST_F(TransportTest, Cleanup) {
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());
    EXPECT_EQ(ad_transport_peer_table_cleanup(), AD_PEER_TABLE_OK);
    EXPECT_EQ(ad_transport_get_global_peer_table(), nullptr);
}
