#include <iostream>
#include <QCoreApplication>
#include "sniffer.h"

// Scenario 3: Initializing sniffer and fetching network interfaces
int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    std::cout << "--- SCENARIO 3: Sniffer interfaces listing ---" << std::endl;

    std::cout << "Fetching available network interfaces..." << std::endl;
    auto interfaces = Sniffer::getAvailableInterfaces();

    if (interfaces.empty()) {
        std::cout << "No network interfaces found. You might need to run as administrator or verify libpcap/npcap installation." << std::endl;
    } else {
        std::cout << "Found " << interfaces.size() << " interface(s):" << std::endl;
        for (const auto& iface : interfaces) {
            std::cout << " - Name: " << iface.name.toStdString() << std::endl;
            std::cout << "   Description: " << iface.description.toStdString() << std::endl << std::endl;
        }
    }

    return 0;
}
