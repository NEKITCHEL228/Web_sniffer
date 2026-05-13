#include <catch2/catch_test_macros.hpp>
#include "packetfactory.h"
#include <vector>

TEST_CASE("PacketFactory creates packets correctly", "[PacketFactory]") {
    SECTION("Too short data") {
        std::vector<unsigned char> data(10, 0); // Too short for even Ethernet
        auto packet = PacketFactory::createPacket(data.data(), data.size());
        REQUIRE(packet == nullptr);
    }

    SECTION("Valid UDP Packet Parsing") {
        // Construct a dummy Ethernet + IP + UDP packet
        std::vector<unsigned char> data(50, 0);
        // Ethernet header (14 bytes)
        data[12] = 0x08; data[13] = 0x00; // IPv4

        // IP header (20 bytes) starts at 14
        data[14] = 0x45; // Version 4, IHL 5
        data[23] = 17; // UDP protocol

        // Source IP (192.168.1.1)
        data[26] = 192; data[27] = 168; data[28] = 1; data[29] = 1;
        // Dest IP (10.0.0.1)
        data[30] = 10; data[31] = 0; data[32] = 0; data[33] = 1;

        // UDP Header starts at 34
        // Src Port (1234)
        data[34] = (1234 >> 8) & 0xFF; data[35] = 1234 & 0xFF;
        // Dest Port (80)
        data[36] = (80 >> 8) & 0xFF; data[37] = 80 & 0xFF;

        auto packet = PacketFactory::createPacket(data.data(), data.size());
        REQUIRE(packet != nullptr);
        REQUIRE(packet->getProtocol() == "UDP");
        REQUIRE(packet->getSource() == "192.168.1.1");
        REQUIRE(packet->getDestination() == "10.0.0.1");
        REQUIRE(packet->getSrcPort() == 1234);
        REQUIRE(packet->getDestPort() == 80);
    }
}
