#include <iostream>
#include <vector>
#include <QCoreApplication>
#include "packet.h"
#include "filterparser.h"

// Scenario 4: Complex filtering with complex logical queries
int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    std::cout << "--- SCENARIO 4: Complex Filter Evaluation ---" << std::endl;

    std::vector<std::shared_ptr<Packet>> rawPackets;
    rawPackets.push_back(std::make_shared<TcpPacket>("192.168.1.1", "10.0.0.1", 1500, 1234, 80));
    rawPackets.push_back(std::make_shared<TcpPacket>("192.168.1.1", "10.0.0.2", 1500, 1234, 443));
    rawPackets.push_back(std::make_shared<UdpPacket>("192.168.1.2", "10.0.0.2", 100, 53, 53));
    rawPackets.push_back(std::make_shared<IcmpPacket>("192.168.1.3", "10.0.0.3", 64, 8));

    QString complexQuery = "(ip.src == 192.168.1.1 and tcp.port == 443) or ip.proto == UDP";
    auto filterAST = FilterParser::parse(complexQuery);

    if (!filterAST) {
        std::cerr << "Failed to parse filter!" << std::endl;
        return 1;
    }

    int count = 0;
    for(auto pkt : rawPackets) {
        if (filterAST->evaluate(pkt)) {
            count++;
        }
    }

    std::cout << "Successfully matched " << count << " packets matching complex query." << std::endl;
    // Expected: 1 packet matching tcp.port 443, 1 packet matching UDP -> 2 packets.
    if (count == 2) {
        return 0;
    }
    return 1;
}
