#include <catch2/catch_test_macros.hpp>
#include "packet.h"

TEST_CASE("Packet implementations", "[Packet]") {
    SECTION("TcpPacket getters") {
        TcpPacket pkt("1.1.1.1", "2.2.2.2", 100, 1234, 80);
        REQUIRE(pkt.getSource() == "1.1.1.1");
        REQUIRE(pkt.getDestination() == "2.2.2.2");
        REQUIRE(pkt.getSize() == 100);
        REQUIRE(pkt.getProtocol() == "TCP");
        REQUIRE(pkt.getSrcPort() == 1234);
        REQUIRE(pkt.getDestPort() == 80);

        QString info = pkt.getInfo();
        REQUIRE(info.contains("1234", Qt::CaseInsensitive));
        REQUIRE(info.contains("80", Qt::CaseInsensitive));
    }

    SECTION("UdpPacket getters") {
        UdpPacket pkt("1.1.1.1", "2.2.2.2", 80, 53, 53);
        REQUIRE(pkt.getSource() == "1.1.1.1");
        REQUIRE(pkt.getDestination() == "2.2.2.2");
        REQUIRE(pkt.getSize() == 80);
        REQUIRE(pkt.getProtocol() == "UDP");
        REQUIRE(pkt.getSrcPort() == 53);
        REQUIRE(pkt.getDestPort() == 53);

        QString info = pkt.getInfo();
        REQUIRE(info.contains("53", Qt::CaseInsensitive));
    }

    SECTION("IcmpPacket getters") {
        IcmpPacket pkt("1.1.1.1", "2.2.2.2", 60, 8);
        REQUIRE(pkt.getSource() == "1.1.1.1");
        REQUIRE(pkt.getDestination() == "2.2.2.2");
        REQUIRE(pkt.getSize() == 60);
        REQUIRE(pkt.getProtocol() == "ICMP");
        // Ports should be 0 by default
        REQUIRE(pkt.getSrcPort() == 0);
        REQUIRE(pkt.getDestPort() == 0);

        QString info = pkt.getInfo();
        REQUIRE(info.contains("8", Qt::CaseInsensitive));
    }
}
