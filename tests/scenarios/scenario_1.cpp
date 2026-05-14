#include <iostream>
#include <vector>
#include <QString>
#include <QCoreApplication>
#include "packet.h"
#include "packetfactory.h"
#include "filemanager.h"
#include "filterparser.h"

// Scenario 1: Capturing (simulated), Filtering and Saving to PCAP
int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    std::cout << "--- SCENARIO 1: Generate, Filter, and Save ---" << std::endl;

    // 1. Generate fake packets
    std::vector<std::shared_ptr<Packet>> rawPackets;
    rawPackets.push_back(std::make_shared<TcpPacket>("192.168.1.1", "10.0.0.1", 1500, 1234, 80));
    rawPackets.push_back(std::make_shared<UdpPacket>("192.168.1.2", "10.0.0.2", 100, 53, 53));
    rawPackets.push_back(std::make_shared<IcmpPacket>("192.168.1.3", "10.0.0.3", 64, 8));
    rawPackets.push_back(std::make_shared<TcpPacket>("10.0.0.1", "192.168.1.1", 200, 80, 1234));

    std::cout << "Generated " << rawPackets.size() << " packets." << std::endl;

    // 2. Apply a filter "tcp.port == 80"
    QString filterQuery = "tcp.port == 80";
    auto filterAST = FilterParser::parse(filterQuery);

    std::vector<std::shared_ptr<Packet>> filteredPackets;
    if (filterAST) {
        for (auto p : rawPackets) {
            if (filterAST->evaluate(p)) {
                filteredPackets.push_back(p);
            }
        }
    } else {
        std::cerr << "Failed to parse filter!" << std::endl;
        return 1;
    }

    std::cout << "Applied filter '" << filterQuery.toStdString() << "'. Remaining packets: " << filteredPackets.size() << std::endl;

    // 3. Save to PCAP
    QString filename = "scenario1_output.pcap";
    if (FileManager::getInstance()->saveToPcap(filename, filteredPackets)) {
        std::cout << "Successfully saved to " << filename.toStdString() << std::endl;
    } else {
        std::cerr << "Failed to save pcap." << std::endl;
        return 1;
    }

    return 0;
}
