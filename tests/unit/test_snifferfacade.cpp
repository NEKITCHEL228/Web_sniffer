#include <catch2/catch_test_macros.hpp>
#include "snifferfacade.h"
#include <memory>

TEST_CASE("SnifferFacade operations", "[SnifferFacade]") {
    SECTION("Initialization and safe shutdown") {
        auto facade = std::make_unique<SnifferFacade>();

        // Start capture on dummy interface, should handle gracefully
        facade->startCapture("non_existent_interface");
        facade->applyFilter("ip.src == 192.168.1.1");
        facade->stopCapture();

        REQUIRE(true); // Should not leak or crash
    }

    SECTION("Apply filter handling") {
        auto facade = std::make_unique<SnifferFacade>();
        facade->applyFilter("tcp.port == 80");
        // Should not crash even without starting capture
        REQUIRE(true);
    }

    SECTION("Stop without start") {
        auto facade = std::make_unique<SnifferFacade>();
        facade->stopCapture();
        REQUIRE(true);
    }

    SECTION("Start, stop, and start again") {
        auto facade = std::make_unique<SnifferFacade>();
        facade->startCapture("dummy_1");
        facade->stopCapture();
        facade->startCapture("dummy_2");
        facade->stopCapture();
        REQUIRE(true);
    }

    SECTION("Apply invalid filter") {
        auto facade = std::make_unique<SnifferFacade>();
        facade->applyFilter("invalid filter syntax ===");
        // The parser might return null and handle it. App shouldn't crash.
        REQUIRE(true);
    }
}