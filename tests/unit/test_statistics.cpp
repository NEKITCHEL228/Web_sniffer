#include <catch2/catch_test_macros.hpp>
#include "statistics.h"

TEST_CASE("Statistics core functionality", "[Statistics]") {
    Statistics* stats = Statistics::getInstance();
    stats->reset();

    SECTION("Initial state is zero") {
        REQUIRE(stats->getTotalPackets() == 0);
        REQUIRE(stats->getTotalVolume() == 0);
        REQUIRE(stats->getProtocolStats().isEmpty());
    }

    SECTION("Updates correctly") {
        auto p1 = std::make_shared<TcpPacket>("1.1.1.1", "2.2.2.2", 100, 80, 443);
        auto p2 = std::make_shared<UdpPacket>("1.1.1.1", "2.2.2.2", 200, 53, 53);
        auto p3 = std::make_shared<TcpPacket>("1.1.1.1", "2.2.2.2", 50, 80, 443);

        stats->update(p1);
        stats->update(p2);
        stats->update(p3);

        REQUIRE(stats->getTotalPackets() == 3);
        REQUIRE(stats->getTotalVolume() == 350);

        auto pstats = stats->getProtocolStats();
        REQUIRE(pstats.value("TCP") == 2);
        REQUIRE(pstats.value("UDP") == 1);
        REQUIRE(pstats.value("ICMP") == 0);
    }

    SECTION("Reset clears all data") {
        auto p1 = std::make_shared<TcpPacket>("1.1.1.1", "2.2.2.2", 100, 80, 443);
        stats->update(p1);

        stats->reset();

        REQUIRE(stats->getTotalPackets() == 0);
        REQUIRE(stats->getTotalVolume() == 0);
        REQUIRE(stats->getProtocolStats().isEmpty());
    }

    SECTION("Large number of packets update") {
        for (int i = 0; i < 1000; ++i) {
            auto p = std::make_shared<TcpPacket>("10.0.0.1", "10.0.0.2", 10, 80, 443);
            stats->update(p);
        }
        REQUIRE(stats->getTotalPackets() == 1000);
        REQUIRE(stats->getTotalVolume() == 10000);
        REQUIRE(stats->getProtocolStats().value("TCP") == 1000);
    }

    SECTION("Different protocols update correctly") {
        auto pIcmp = std::make_shared<IcmpPacket>("1.1.1.1", "2.2.2.2", 50, 8);
        stats->update(pIcmp);

        REQUIRE(stats->getTotalPackets() == 1);
        REQUIRE(stats->getTotalVolume() == 50);
        REQUIRE(stats->getProtocolStats().value("ICMP") == 1);
        REQUIRE(stats->getProtocolStats().value("TCP") == 0); // TCP doesn't exist
    }

    SECTION("Consecutive resets") {
        auto p = std::make_shared<TcpPacket>("1.1.1.1", "2.2.2.2", 100, 80, 443);
        stats->update(p);

        stats->reset();
        stats->reset(); // shouldn't crash

        REQUIRE(stats->getTotalPackets() == 0);
        REQUIRE(stats->getTotalVolume() == 0);
        REQUIRE(stats->getProtocolStats().isEmpty());
    }
}
