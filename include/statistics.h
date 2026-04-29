#ifndef STATISTICS_H
#define STATISTICS_H

#include "packet.h"
#include <QMap>

class Statistics {
public:
    static Statistics* getInstance();
    void update(std::shared_ptr<Packet> p);
    void reset();

    int getTotalPackets() const { return totalPackets; }
    long long getTotalVolume() const { return totalVolume; }
    QMap<QString, int> getProtocolStats() const { return protocolStats; }

private:
    Statistics() : totalPackets(0), totalVolume(0) {}
    static Statistics* instance;

    int totalPackets;
    long long totalVolume;
    QMap<QString, int> protocolStats;
};

#endif
