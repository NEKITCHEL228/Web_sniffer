#include <catch2/catch_test_macros.hpp>
#include "filterparser.h"
#include "packet.h"

TEST_CASE("Filter parser syntax and evaluation", "[FilterParser]") {

    auto packet = std::make_shared<TcpPacket>("192.168.1.100", "10.0.0.5", 1500, 443, 8080);
    // packet proto is TCP

    SECTION("Empty or invalid query") {
        REQUIRE(FilterParser::parse("") == nullptr);
        REQUIRE(FilterParser::parse("   ") == nullptr);
    }

    SECTION("Simple field equality") {
        auto ast = FilterParser::parse("ip.src == 192.168.1.100");
        REQUIRE(ast != nullptr);
        REQUIRE(ast->evaluate(packet) == true);

        auto ast2 = FilterParser::parse("ip.src == 1.1.1.1");
        REQUIRE(ast2 != nullptr);
        REQUIRE(ast2->evaluate(packet) == false);
    }

    SECTION("Field inequality") {
        auto ast = FilterParser::parse("tcp.port != 80");
        REQUIRE(ast != nullptr);
        REQUIRE(ast->evaluate(packet) == true);

        auto ast2 = FilterParser::parse("tcp.port != 443");
        REQUIRE(ast2 != nullptr);
        // Src port is 443, so evaluates to true? Wait, tcp.port matches src or dst.
        // It matches 443, so match is true. op == "!=" returns !match -> false.
        REQUIRE(ast2->evaluate(packet) == false);
    }

    SECTION("Logical combinations") {
        auto ast = FilterParser::parse("ip.src == 192.168.1.100 and tcp.dstport == 8080");
        REQUIRE(ast != nullptr);
        REQUIRE(ast->evaluate(packet) == true);

        auto ast2 = FilterParser::parse("ip.src == 1.2.3.4 or tcp.dstport == 8080");
        REQUIRE(ast2 != nullptr);
        REQUIRE(ast2->evaluate(packet) == true);
    }

    SECTION("Parentheses and NOT") {
        auto ast = FilterParser::parse("!(ip.src == 1.1.1.1)");
        REQUIRE(ast != nullptr);
        REQUIRE(ast->evaluate(packet) == true);

        auto ast2 = FilterParser::parse("not (tcp.port == 443 and ip.dst == 10.0.0.5)");
        REQUIRE(ast2 != nullptr);
        // inner is true, not true -> false
        REQUIRE(ast2->evaluate(packet) == false);
    }
}
