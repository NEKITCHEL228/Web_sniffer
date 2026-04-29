#include "analyzer.h"
#include "statistics.h"

Analyzer::Analyzer(QObject *parent) : QObject(parent), currentStrategy(nullptr) {}

void Analyzer::onPacketCaptured(std::shared_ptr<Packet> packet) {
    if (currentStrategy && !currentStrategy->applyFilter(packet)) {
        return;
    }
    Statistics::getInstance()->update(packet);
    emit packetProcessed(packet);
}
