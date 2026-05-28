#include <iostream>
#include <QCoreApplication>
#include <QObject>
#include <QTimer>
#include "anomalydetector.h"
#include "packet.h"

// Scenario 5: AnomalyDetector processing
int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    std::cout << "--- SCENARIO 5: AnomalyDetector Processing ---" << std::endl;

    auto detector = AnomalyDetector::getInstance();

    auto p1 = std::make_shared<TcpPacket>("1.1.1.1", "2.2.2.2", 100, 80, 443);
    auto p2 = std::make_shared<IcmpPacket>("1.1.1.1", "2.2.2.2", 100, 8);
    auto p3 = std::make_shared<TcpPacket>("3.3.3.3", "4.4.4.4", 100, 21, 5000); // Suspicious port

    detector->update(p1);
    detector->update(p2);
    detector->update(p3);

    QTimer::singleShot(100, [&app, detector]() {
        if (detector->getSuspiciousPortPackets() > 0) {
            std::cout << "Anomalies successfully detected by AnomalyDetector." << std::endl;
            app.quit();
        } else {
            app.exit(1);
        }
    });

    return app.exec();
}
