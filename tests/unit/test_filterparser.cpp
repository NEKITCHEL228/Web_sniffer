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

    SECTION("Protocol field") {
        auto ast = FilterParser::parse("ip.proto == TCP");
        REQUIRE(ast != nullptr);
        REQUIRE(ast->evaluate(packet) == true);

        auto ast2 = FilterParser::parse("ip.proto == UDP");
        REQUIRE(ast2 != nullptr);
        REQUIRE(ast2->evaluate(packet) == false);

        auto ast3 = FilterParser::parse("ip.proto != UDP");
        REQUIRE(ast3 != nullptr);
        REQUIRE(ast3->evaluate(packet) == true);
    }

    SECTION("Complex expression with multiple nesting") {
        auto ast = FilterParser::parse("(ip.src == 192.168.1.100 or ip.dst == 192.168.1.100) and (tcp.port == 443 or udp.port == 443)");
        REQUIRE(ast != nullptr);
        REQUIRE(ast->evaluate(packet) == true);

        auto ast2 = FilterParser::parse("((ip.src == 1.1.1.1) or (ip.dst == 10.0.0.5)) and not (tcp.port == 8080)");
        REQUIRE(ast2 != nullptr);
        REQUIRE(ast2->evaluate(packet) == false); // ip.dst is 10.0.0.5 (true) and not (true) => true and false => false
    }

    SECTION("Invalid syntax") {
        auto ast = FilterParser::parse("ip.src == ");
        REQUIRE(ast == nullptr);

        auto ast2 = FilterParser::parse("== 192.168.1.100");
        REQUIRE(ast2 != nullptr);
        REQUIRE(ast2->evaluate(packet) == false);

        auto ast3 = FilterParser::parse("ip.src == 192.168...100 and");
        // Could be parsed as invalid AST based on implementation, let's just make sure it doesn't crash
        // Our simplified parser might handle this in ways that might be null or return incomplete ast
    }
}
