#include "filterstrategy.h"

bool IpFilterStrategy::applyFilter(std::shared_ptr<Packet> p) {
    return p->getSource().contains(targetIp) || p->getDestination().contains(targetIp);
}

bool ProtocolFilterStrategy::applyFilter(std::shared_ptr<Packet> p) {
    return p->getProtocol().toUpper() == targetProtocol.toUpper();
}

bool PortFilterStrategy::applyFilter(std::shared_ptr<Packet> p) {
    if (p->getProtocol().toUpper() == "TCP" || p->getProtocol().toUpper() == "UDP") {
        return p->getSrcPort() == targetPort || p->getDestPort() == targetPort;
    }
    return false;
}
