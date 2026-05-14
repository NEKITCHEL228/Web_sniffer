#include <catch2/catch_test_macros.hpp>
#include "filemanager.h"
#include <QFile>
#include <QDir>
#include <iostream>

TEST_CASE("FileManager functionality", "[FileManager]") {
    FileManager* fm = FileManager::getInstance();
    QString testFile = QDir::tempPath() + "/test_sniff.pcap";

    SECTION("Save empty packets list") {
        std::vector<std::shared_ptr<Packet>> emptyList;
        bool result = fm->saveToPcap(testFile, emptyList);
        REQUIRE(result == true);
        REQUIRE(QFile::exists(testFile));
        QFile::remove(testFile);
    }

    SECTION("Save and load packets") {
        auto pkt = std::make_shared<TcpPacket>("192.168.1.1", "10.0.0.1", 100, 1234, 80);

        std::vector<std::shared_ptr<Packet>> list = { pkt };
        bool saved = fm->saveToPcap(testFile, list);
        REQUIRE(saved == true);

        auto loaded = fm->loadFromPcap(testFile);
        REQUIRE(loaded.size() == 1);

        auto first = loaded[0];
        REQUIRE(first->getProtocol() == "TCP");
        REQUIRE(first->getSource() == "192.168.1.1");
        REQUIRE(first->getDestination() == "10.0.0.1");
        // Ports get correctly loaded assuming PacketFactory works inside loadFromPcap
        REQUIRE(first->getSrcPort() == 1234);
        REQUIRE(first->getDestPort() == 80);

        QFile::remove(testFile);
    }

    SECTION("Load non-existent file") {
        auto loaded = fm->loadFromPcap("does_not_exist_file.pcap");
        REQUIRE(loaded.empty() == true);
    }

    SECTION("Save multiple mixed packets") {
        auto p1 = std::make_shared<TcpPacket>("1.1.1.1", "2.2.2.2", 100, 100, 200);
        auto p2 = std::make_shared<UdpPacket>("3.3.3.3", "4.4.4.4", 200, 300, 400);
        auto p3 = std::make_shared<IcmpPacket>("5.5.5.5", "6.6.6.6", 300, 8);

        std::vector<std::shared_ptr<Packet>> list = { p1, p2, p3 };
        bool saved = fm->saveToPcap(testFile, list);
        REQUIRE(saved == true);

        auto loaded = fm->loadFromPcap(testFile);
        REQUIRE(loaded.size() == 3);

        REQUIRE(loaded[0]->getProtocol() == "TCP");
        REQUIRE(loaded[1]->getProtocol() == "UDP");
        REQUIRE(loaded[2]->getProtocol() == "ICMP");

        REQUIRE(loaded[1]->getSource() == "3.3.3.3");
        REQUIRE(loaded[1]->getDestPort() == 400);

        REQUIRE(loaded[2]->getDestination() == "6.6.6.6");

        QFile::remove(testFile);
    }

    SECTION("Invalid output path") {
        std::vector<std::shared_ptr<Packet>> emptyList;
        // Windows/Unix root write without permissions or invalid path
        bool result = fm->saveToPcap("/invalid_dir_that_does_not_exist/file.pcap", emptyList);
        // It might be possible that it just fails
        REQUIRE(result == false);
    }
}
