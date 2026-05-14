#include <iostream>
#include <QCoreApplication>
#include <QObject>
#include <QTimer>
#include "analyzer.h"
#include "packet.h"

// Scenario 5: Analyzer packet processing and signals
int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    std::cout << "--- SCENARIO 5: Analyzer Processing ---" << std::endl;

    Analyzer analyzer;
    int processedCount = 0;

    QObject::connect(&analyzer, &Analyzer::packetProcessed, [&processedCount](std::shared_ptr<Packet> p) {
        std::cout << "Analyzer received packet: " << p->getInfo().toStdString() << std::endl;
        processedCount++;
    });

    auto p1 = std::make_shared<TcpPacket>("1.1.1.1", "2.2.2.2", 100, 80, 443);
    auto p2 = std::make_shared<IcmpPacket>("1.1.1.1", "2.2.2.2", 100, 8);

    analyzer.onPacketCaptured(p1);
    analyzer.onPacketCaptured(p2);

    QTimer::singleShot(100, [&app, &processedCount]() {
        if (processedCount == 2) {
            std::cout << "All packets successfully processed by Analyzer." << std::endl;
            app.quit();
        } else {
            app.exit(1);
        }
    });

    return app.exec();
}
