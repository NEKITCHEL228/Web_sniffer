#include <iostream>
#include <QCoreApplication>
#include "filemanager.h"
#include "statistics.h"

// Scenario 2: Load packets from PCAP and collect statistics
int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    std::cout << "--- SCENARIO 2: Load PCAP and Analyze Statistics ---" << std::endl;

    QString filename = "scenario1_output.pcap";
    auto packets = FileManager::getInstance()->loadFromPcap(filename);

    if (packets.empty()) {
        std::cerr << "Failed to run. Scenario 2 requires scenario 1 to run first, or file is missing." << std::endl;
        return 1;
    }

    std::cout << "Loaded " << packets.size() << " packets from " << filename.toStdString() << std::endl;

    Statistics::getInstance()->reset();

    for (auto p : packets) {
        Statistics::getInstance()->update(p);
    }

    std::cout << "Total Packets: " << Statistics::getInstance()->getTotalPackets() << std::endl;
    std::cout << "Total Volume: " << Statistics::getInstance()->getTotalVolume() << " bytes" << std::endl;

    auto pstats = Statistics::getInstance()->getProtocolStats();
    for (auto it = pstats.begin(); it != pstats.end(); ++it) {
        std::cout << "Protocol " << it.key().toStdString() << ": " << it.value() << " packets" << std::endl;
    }

    return 0;
}
