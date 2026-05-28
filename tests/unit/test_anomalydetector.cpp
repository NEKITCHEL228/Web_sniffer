#include <catch2/catch_test_macros.hpp>
#include "anomalydetector.h"
#include "packet.h"

TEST_CASE("AnomalyDetector core functionality", "[AnomalyDetector]") {
    AnomalyDetector* detector = AnomalyDetector::getInstance();
    detector->reset();

    SECTION("Initial state is zero") {
        REQUIRE(detector->getSynFloodCount() == 0);
        REQUIRE(detector->getSuspiciousPortPackets() == 0);
        REQUIRE(detector->getDosAttackers().isEmpty());
    }

    SECTION("Suspicious ports detection") {
        // Safe port
        auto normalPacket = std::make_shared<TcpPacket>("1.1.1.1", "2.2.2.2", 100, 80, 443);
        REQUIRE_FALSE(detector->isSuspiciousPort(normalPacket));

        // FTP Port 21
        auto ftpPacket = std::make_shared<TcpPacket>("1.1.1.1", "2.2.2.2", 100, 21, 1024);
        REQUIRE(detector->isSuspiciousPort(ftpPacket));

        // Telnet Port 23
        auto telnetPacket = std::make_shared<UdpPacket>("1.1.1.1", "2.2.2.2", 100, 1024, 23);
        REQUIRE(detector->isSuspiciousPort(telnetPacket));

        // SMB Port 445
        auto smbPacket = std::make_shared<TcpPacket>("1.1.1.1", "2.2.2.2", 100, 445, 1024);
        REQUIRE(detector->isSuspiciousPort(smbPacket));

        // RDP Port 3389
        auto rdpPacket = std::make_shared<TcpPacket>("1.1.1.1", "2.2.2.2", 100, 1024, 3389);
        REQUIRE(detector->isSuspiciousPort(rdpPacket));
    }

    SECTION("SYN Flood packet detection (TCP Handshake and flags)") {
        // In our sniffer, isSYNFlood checks the rawData of the TCP Packet.
        // Let's craft a raw TCP packet with SYN set but ACK clear.
        std::vector<uint8_t> rawSynData(40, 0);
        rawSynData[12] = 0x08; // EtherType IPv4 high byte
        rawSynData[13] = 0x00; // EtherType IPv4 low byte
        rawSynData[14] = 0x45; // Version / IHL (5 * 4 = 20 bytes IP Header length)

        // Host payload offset = 14 + 20 = 34
        // TCP flags field is offset 13 of the TCP header, which means 34 + 13 = 47.
        // Let's expand our raw data to 50 bytes.
        rawSynData.resize(60, 0);
        rawSynData[47] = 0x02; // SYN flag only (0x02)

        auto mockSynPacket = std::make_shared<TcpPacket>("1.1.1.1", "2.2.2.2", 60, 1024, 80);
        mockSynPacket->setRawData(rawSynData);

        REQUIRE(detector->isSYNFlood(mockSynPacket));

        // Now test with SYN and ACK both set
        rawSynData[47] = 0x12; // SYN (0x02) + ACK (0x10) = 0x12
        mockSynPacket->setRawData(rawSynData);
        REQUIRE_FALSE(detector->isSYNFlood(mockSynPacket));
    }

    SECTION("Updates counter correctly") {
        auto ftpPacket = std::make_shared<TcpPacket>("1.1.1.1", "2.2.2.2", 100, 21, 1024);
        detector->update(ftpPacket);

        REQUIRE(detector->getSuspiciousPortPackets() == 1);
    }

    SECTION("DoS attackers detection") {
        // Send 1001 packets from 5.5.5.5
        for (int i = 0; i < 1002; ++i) {
            auto p = std::make_shared<IcmpPacket>("5.5.5.5", "2.2.2.2", 60, 8);
            detector->update(p);
        }

        REQUIRE(detector->getDosAttackers().contains("5.5.5.5"));
    }

    SECTION("Reset clears state") {
        auto ftpPacket = std::make_shared<TcpPacket>("1.1.1.1", "2.2.2.2", 100, 21, 1024);
        detector->update(ftpPacket);
        REQUIRE(detector->getSuspiciousPortPackets() == 1);

        detector->reset();
        REQUIRE(detector->getSuspiciousPortPackets() == 0);
        REQUIRE(detector->getDosAttackers().isEmpty());
    }
}
