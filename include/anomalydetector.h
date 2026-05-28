#ifndef ANOMALYDETECTOR_H
#define ANOMALYDETECTOR_H

#include "packet.h"
#include <QMap>
#include <QStringList>

class AnomalyDetector {
public:
    static AnomalyDetector* getInstance();

    void update(std::shared_ptr<Packet> p);
    void reset();

    int getSynFloodCount() const { return synFloodCount; }
    int getSuspiciousPortPackets() const { return suspiciousPortPackets; }
    QStringList getDosAttackers() const { return dosAttackers; }

    bool isSYNFlood(const std::shared_ptr<Packet>& p) const;
    bool isSuspiciousPort(const std::shared_ptr<Packet>& p) const;

private:
    AnomalyDetector() : synFloodCount(0), suspiciousPortPackets(0) {}
    static AnomalyDetector* instance;

    int synFloodCount;
    int suspiciousPortPackets;
    QMap<QString, int> ipPacketCount;
    QStringList dosAttackers;
};

#endif
