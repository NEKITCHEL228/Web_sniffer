#include "statistics.h"

Statistics* Statistics::instance = nullptr;

Statistics* Statistics::getInstance() {
    if (!instance) instance = new Statistics();
    return instance;
}

void Statistics::update(std::shared_ptr<Packet> p) {
    totalPackets++;
    totalVolume += p->getSize();
    protocolStats[p->getProtocol()]++;
}

void Statistics::reset() {
    totalPackets = 0;
    totalVolume = 0;
    protocolStats.clear();
}
