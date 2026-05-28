#include "anomalydetector.h"

AnomalyDetector* AnomalyDetector::instance = nullptr;

AnomalyDetector* AnomalyDetector::getInstance() {
    if (!instance) instance = new AnomalyDetector();
    return instance;
}

bool AnomalyDetector::isSuspiciousPort(const std::shared_ptr<Packet>& p) const {
    if (p->getProtocol() == "TCP" || p->getProtocol() == "UDP") {
        int srcPort = p->getSrcPort();
        int destPort = p->getDestPort();
        return (srcPort == 21 || destPort == 21 || srcPort == 23 || destPort == 23 ||
                srcPort == 445 || destPort == 445 || srcPort == 3389 || destPort == 3389);
    }
    return false;
}

bool AnomalyDetector::isSYNFlood(const std::shared_ptr<Packet>& p) const {
    if (p->getProtocol() == "TCP") {
        const auto& rawData = p->getRawData();
        if (rawData.size() >= 34) {
            uint16_t etherType = (rawData[12] << 8) | rawData[13];
            if (etherType == 0x0800) { // IPv4
                int ipHeaderLen = (rawData[14] & 0x0F) * 4;
                size_t payloadOffset = 14 + ipHeaderLen;
                if (rawData.size() >= payloadOffset + 14) {
                    uint8_t flags = rawData[payloadOffset + 13];
                    bool syn = (flags & 0x02) != 0;
                    bool ack = (flags & 0x10) != 0;
                    return (syn && !ack);
                }
            }
        }
    }
    return false;
}

void AnomalyDetector::update(std::shared_ptr<Packet> p) {
    if (isSuspiciousPort(p)) suspiciousPortPackets++;
    if (isSYNFlood(p)) synFloodCount++;

    ipPacketCount[p->getSource()]++;
    if (ipPacketCount[p->getSource()] > 1000 && !dosAttackers.contains(p->getSource())) {
        dosAttackers.append(p->getSource());
    }
}

void AnomalyDetector::reset() {
    synFloodCount = 0;
    suspiciousPortPackets = 0;
    ipPacketCount.clear();
    dosAttackers.clear();
}
