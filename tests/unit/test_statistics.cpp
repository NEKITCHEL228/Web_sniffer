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
}
