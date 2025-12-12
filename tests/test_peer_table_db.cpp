#include "../../../prebuilt/googletest/googletest/include/gtest/gtest.h"

extern "C" {
#include "../include/ad_transport.h"
}

#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <fstream>
#include <unistd.h>

/* ---------------------------------------------
 * Helper to create a temporary INI file
 * --------------------------------------------- */
static std::string write_temp_ini() {
    std::string path = "/tmp/ad_transport_test.ini";
    std::ofstream f(path);
    f <<
    "[peer_table]\n"
    "capacity = 4\n"
    "persist_interval = 10\n"
    "db_path = /tmp/test_peers.db\n"
    "\n"
    "[peer:peer1]\n"
    "real_addr = 10.0.0.1:5555\n"
    "routes = 192.168.1.0/24, 10.10.0.0/16\n"
    "active = 1\n"
    "\n"
    "[peer:peer2]\n"
    "real_addr = 172.16.1.1:8080\n"
    "routes = 172.16.0.0/16\n"
    "active = 1\n";
    f.close();
    return path;
}

/* ---------------------------------------------
 * Fixture
 * --------------------------------------------- */
class TransportTest : public ::testing::Test {
protected:
    void TearDown() override {
        ad_transport_peer_table_cleanup();
    }
};

/* ---------------------------------------------
 * Init from config
 * --------------------------------------------- */
TEST_F(TransportTest, InitFromConfig) {
    auto ini = write_temp_ini();
    EXPECT_EQ(ad_transport_peer_table_init_from_config(ini.c_str()),
              AD_TRANSPORT_OK);

    ad_transport_peer_table_t* t = ad_get_global_peer_table();
    ASSERT_NE(t, nullptr);
    EXPECT_GE(t->capacity, 4);
    EXPECT_EQ(t->persist_interval_sec, 10u);
    ASSERT_EQ(t->count, 2u);
}

/* ---------------------------------------------
 * Add Peer
 * --------------------------------------------- */
TEST_F(TransportTest, AddPeer) {
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());

    ad_transport_peer_t p{};
    p.peer_id = strdup("manual_peer");
    p.active = 1;

    // Add a route
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "1.2.3.4", &addr.sin_addr);

    p.route_count = 1;
    p.routes = (sockaddr_in*)calloc(1, sizeof(sockaddr_in));
    p.route_prefixlen = (uint8_t*)calloc(1, sizeof(uint8_t));
    p.routes[0] = addr;
    p.route_prefixlen[0] = 24;

    EXPECT_EQ(ad_transport_peer_table_add(&p), AD_PEER_TABLE_OK);

    free(p.peer_id);
    free(p.routes);
    free(p.route_prefixlen);

    EXPECT_EQ(ad_get_global_peer_table()->count, 3u);
}

/* ---------------------------------------------
 * Remove
 * --------------------------------------------- */
TEST_F(TransportTest, RemovePeer) {
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());
    EXPECT_EQ(ad_transport_peer_table_remove("peer1"), AD_PEER_TABLE_OK);
    EXPECT_EQ(ad_get_global_peer_table()->count, 1u);
}

/* ---------------------------------------------
 * Lookup – LPM match
 * --------------------------------------------- */
TEST_F(TransportTest, LookupPeer) {
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());

    struct sockaddr_in q{};
    q.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.1.55", &q.sin_addr);  // matches peer1 /24

    ad_transport_peer_t* p = ad_transport_peer_table_lookup(&q);
    ASSERT_NE(p, nullptr);
    EXPECT_STREQ(p->peer_id, "peer1");
}

/* ---------------------------------------------
 * Lookup – No match
 * --------------------------------------------- */
TEST_F(TransportTest, LookupNoMatch) {
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());

    struct sockaddr_in q{};
    q.sin_family = AF_INET;
    inet_pton(AF_INET, "8.8.8.8", &q.sin_addr);

    ad_transport_peer_t* p = ad_transport_peer_table_lookup(&q);
    EXPECT_EQ(p, nullptr);
}

/* ---------------------------------------------
 * Cleanup
 * --------------------------------------------- */
TEST_F(TransportTest, Cleanup) {
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());
    EXPECT_EQ(ad_transport_peer_table_cleanup(), AD_PEER_TABLE_OK);
    EXPECT_EQ(ad_get_global_peer_table(), nullptr);
}

/* ---------------------------------------------
 * Get global table copy
 * --------------------------------------------- */
TEST_F(TransportTest, GetTableCopy) {
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());

    auto copy = ad_get_global_peer_table_copy();
    EXPECT_EQ(copy.count, 2u);
    EXPECT_NE(copy.entries, nullptr);
}

/* ---------------------------------------------
 * DB Open/Close
 * --------------------------------------------- */
TEST_F(TransportTest, DBOpenClose) {
    EXPECT_EQ(ad_peer_table_db_open("/tmp/test.db"), AD_PEER_TABLE_OK);
    EXPECT_EQ(ad_peer_table_db_close(), AD_PEER_TABLE_OK);
}

/* ---------------------------------------------
 * Persistence start/stop
 * --------------------------------------------- */
TEST_F(TransportTest, PersistenceThread) {
    ad_transport_peer_table_init_from_config(write_temp_ini().c_str());
    EXPECT_EQ(ad_peer_table_start_persistence(), AD_PEER_TABLE_OK);
    sleep(1); // let it start
    EXPECT_EQ(ad_peer_table_stop_persistence(), AD_PEER_TABLE_OK);
}
