#include <catch2/catch_test_macros.hpp>
#include "filterstrategy.h"
#include "packet.h"

TEST_CASE("Filter strategies", "[FilterStrategy]") {
    auto tcpPkt = std::make_shared<TcpPacket>("192.168.0.1", "10.0.0.1", 100, 1000, 80);
    auto udpPkt = std::make_shared<UdpPacket>("10.0.0.2", "192.168.0.1", 50, 53, 53);

    SECTION("IpFilterStrategy") {
        IpFilterStrategy filter("192.168.0.1");

        // Match source
        REQUIRE(filter.applyFilter(tcpPkt) == true);

        // Match destination
        REQUIRE(filter.applyFilter(udpPkt) == true);

        // No match
        IpFilterStrategy filter2("8.8.8.8");
        REQUIRE(filter2.applyFilter(tcpPkt) == false);
    }

    SECTION("ProtocolFilterStrategy") {
        ProtocolFilterStrategy filter("TCP");

        REQUIRE(filter.applyFilter(tcpPkt) == true);
        REQUIRE(filter.applyFilter(udpPkt) == false);

        ProtocolFilterStrategy filter2("UDP");
        REQUIRE(filter2.applyFilter(udpPkt) == true);
    }

    SECTION("PortFilterStrategy") {
        PortFilterStrategy filter(80);

        // Match destination port
        REQUIRE(filter.applyFilter(tcpPkt) == true);
        // Dest port is 53, src is 53
        REQUIRE(filter.applyFilter(udpPkt) == false);

        PortFilterStrategy filter2(1000);
        // Match src port
        REQUIRE(filter2.applyFilter(tcpPkt) == true);
    }
}
