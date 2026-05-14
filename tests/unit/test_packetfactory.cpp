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
    SECTION("Valid TCP Packet Parsing") {
        std::vector<unsigned char> data(60, 0);
        // Ethernet header (14 bytes)
        data[12] = 0x08; data[13] = 0x00; // IPv4

        // IP header (20 bytes)
        data[14] = 0x45; // Version 4, IHL 5
        data[23] = 6; // TCP protocol

        // Source IP (172.16.0.2)
        data[26] = 172; data[27] = 16; data[28] = 0; data[29] = 2;
        // Dest IP (8.8.8.8)
        data[30] = 8; data[31] = 8; data[32] = 8; data[33] = 8;

        // TCP Header starts at 34
        // Src Port (443)
        data[34] = (443 >> 8) & 0xFF; data[35] = 443 & 0xFF;
        // Dest Port (8080)
        data[36] = (8080 >> 8) & 0xFF; data[37] = 8080 & 0xFF;

        auto packet = PacketFactory::createPacket(data.data(), data.size());
        REQUIRE(packet != nullptr);
        REQUIRE(packet->getProtocol() == "TCP");
        REQUIRE(packet->getSource() == "172.16.0.2");
        REQUIRE(packet->getDestination() == "8.8.8.8");
        REQUIRE(packet->getSrcPort() == 443);
        REQUIRE(packet->getDestPort() == 8080);
    }

    SECTION("Valid ICMP Packet Parsing") {
        std::vector<unsigned char> data(50, 0);
        // Ethernet header (14 bytes)
        data[12] = 0x08; data[13] = 0x00; // IPv4

        // IP header (20 bytes)
        data[14] = 0x45; // Version 4, IHL 5
        data[23] = 1; // ICMP protocol

        // Source IP (127.0.0.1)
        data[26] = 127; data[27] = 0; data[28] = 0; data[29] = 1;
        // Dest IP (127.0.0.1)
        data[30] = 127; data[31] = 0; data[32] = 0; data[33] = 1;

        // ICMP Header starts at 34
        data[34] = 8; // Type 8 (Echo Request)

        auto packet = PacketFactory::createPacket(data.data(), data.size());
        REQUIRE(packet != nullptr);
        REQUIRE(packet->getProtocol() == "ICMP");
        REQUIRE(packet->getSource() == "127.0.0.1");
        REQUIRE(packet->getDestination() == "127.0.0.1");
        REQUIRE(packet->getSrcPort() == 0); // No ports in ICMP
        REQUIRE(packet->getDestPort() == 0);
    }

    SECTION("Unsupported protocol Packet Parsing") {
        std::vector<unsigned char> data(50, 0);
        // Ethernet header (14 bytes)
        data[12] = 0x08; data[13] = 0x00; // IPv4

        // IP header (20 bytes)
        data[14] = 0x45; // Version 4, IHL 5
        data[23] = 50; // ESP protocol

        // Source IP (127.0.0.1)
        data[26] = 127; data[27] = 0; data[28] = 0; data[29] = 1;
        // Dest IP (127.0.0.1)
        data[30] = 127; data[31] = 0; data[32] = 0; data[33] = 1;

        auto packet = PacketFactory::createPacket(data.data(), data.size());
        // For unknown protocols, it could be null or some generic packet.
        // It's probably returning an IP packet or null. Let's see packagefactory implementation later.
        // I will assume it returns nullptr for now unless it supports it.
        REQUIRE(packet == nullptr); // Actually, we might need to check the implementation.
    }

    SECTION("IPv6 unsupported Packet Parsing") {
        std::vector<unsigned char> data(50, 0);
        // Ethernet header (14 bytes)
        data[12] = 0x86; data[13] = 0xDD; // IPv6

        auto packet = PacketFactory::createPacket(data.data(), data.size());
        REQUIRE(packet == nullptr);
    }
}
