#include "statistics.h"

Statistics* Statistics::instance = nullptr;

Statistics* Statistics::getInstance() {
    if (!instance) instance = new Statistics();
    return instance;
}

bool Statistics::isEncrypted(const std::shared_ptr<Packet>& p) const {
    if (p->getProtocol() == "TCP" || p->getProtocol() == "UDP") {
        int srcPort = p->getSrcPort();
        int destPort = p->getDestPort();
        return (srcPort == 443 || destPort == 443);
    }
    return false;
}

bool Statistics::isUnencrypted(const std::shared_ptr<Packet>& p) const {
    if (p->getProtocol() == "TCP" || p->getProtocol() == "UDP") {
        int srcPort = p->getSrcPort();
        int destPort = p->getDestPort();
        return (srcPort != 443 && destPort != 443); // Simplify: anything not 443 is unencrypted for this stat
    }
    return true; // ICMP, etc. are unencrypted
}

bool Statistics::isDNS(const std::shared_ptr<Packet>& p) const {
    if (p->getProtocol() == "TCP" || p->getProtocol() == "UDP") {
        int srcPort = p->getSrcPort();
        int destPort = p->getDestPort();
        return (srcPort == 53 || destPort == 53);
    }
    return false;
}

void Statistics::update(std::shared_ptr<Packet> p) {
    totalPackets++;
    totalVolume += p->getSize();
    protocolStats[p->getProtocol()]++;

    if (isEncrypted(p)) encryptedPackets++;
    if (isUnencrypted(p)) unencryptedPackets++;
    if (isDNS(p)) dnsQueries++;
}

void Statistics::reset() {
    totalPackets = 0;
    totalVolume = 0;
    protocolStats.clear();
    encryptedPackets = 0;
    unencryptedPackets = 0;
    dnsQueries = 0;
}
