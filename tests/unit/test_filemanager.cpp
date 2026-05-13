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
}
