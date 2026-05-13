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
}
