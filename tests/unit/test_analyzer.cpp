#include <catch2/catch_test_macros.hpp>
#include "analyzer.h"
#include "statistics.h"
#include <QSignalSpy>

class MockFilterStrategy : public IFilterStrategy {
public:
    bool shouldPass = true;
    bool applyFilter(std::shared_ptr<Packet> packet) override {
        return shouldPass;
    }
};

TEST_CASE("Analyzer functionality", "[Analyzer]") {
    Analyzer analyzer;
    auto packet = std::make_shared<TcpPacket>("192.168.1.1", "10.0.0.1", 100, 1234, 80);

    SECTION("Packet passes without filter") {
        QSignalSpy spy(&analyzer, &Analyzer::packetProcessed);
        analyzer.onPacketCaptured(packet);
        REQUIRE(spy.count() == 1);
    }

    SECTION("Packet passes with allowing filter") {
        auto filter = std::make_shared<MockFilterStrategy>();
        filter->shouldPass = true;
        analyzer.setFilterStrategy(filter);
        QSignalSpy spy(&analyzer, &Analyzer::packetProcessed);
        analyzer.onPacketCaptured(packet);
        REQUIRE(spy.count() == 1);
    }

    SECTION("Packet dropped with blocking filter") {
        auto filter = std::make_shared<MockFilterStrategy>();
        filter->shouldPass = false;
        analyzer.setFilterStrategy(filter);
        QSignalSpy spy(&analyzer, &Analyzer::packetProcessed);
        analyzer.onPacketCaptured(packet);
        REQUIRE(spy.count() == 0);
    }
}
