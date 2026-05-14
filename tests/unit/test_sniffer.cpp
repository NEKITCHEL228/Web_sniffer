#include <catch2/catch_test_macros.hpp>
#include "sniffer.h"

TEST_CASE("Sniffer basics", "[Sniffer]") {
    SECTION("Get available interfaces") {
        auto interfaces = Sniffer::getAvailableInterfaces();
        // Since we are running in an environment where pcap might find at least one interface,
        // or none if no permissions, we just ensure it doesn't crash.
        // It returns a std::vector<InterfaceInfo>.
        REQUIRE(true); // If we reached here without crashing, that's already good.

        for (const auto& iface : interfaces) {
            REQUIRE(iface.name.length() > 0);
        }
    }

    SECTION("Start and Stop on invalid interface") {
        Sniffer sniffer;
        // Starting on invalid interface "dummy_not_exist" shouldn't crash
        sniffer.startCapture("dummy_not_exist_interface" + QString::number(rand()));

        // It shouldn't block, so stopping should work
        sniffer.stopCapture();
        REQUIRE(true);
    }

    SECTION("Stop sniffer without starting") {
        Sniffer sniffer;
        sniffer.stopCapture();
        REQUIRE(true);
    }

    SECTION("Multiple starts on invalid interfaces") {
        Sniffer sniffer;
        sniffer.startCapture("invalid_1");
        sniffer.startCapture("invalid_2"); // Should handle nicely, maybe ignore or stop first
        sniffer.stopCapture();
        REQUIRE(true);
    }

    SECTION("Available interfaces doesn't throw") {
        REQUIRE_NOTHROW(Sniffer::getAvailableInterfaces());
    }

    SECTION("Destroy sniffer while supposedly capturing") {
        {
            Sniffer sniffer;
            sniffer.startCapture("invalid_interface");
            // destructor called here, shouldn't crash or hang
        }
        REQUIRE(true);
    }
}
