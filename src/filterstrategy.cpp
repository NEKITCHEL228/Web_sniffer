#include "filterstrategy.h"

bool IpFilterStrategy::applyFilter(std::shared_ptr<Packet> p) {
    return p->getSource().contains(targetIp) || p->getDestination().contains(targetIp);
}

bool ProtocolFilterStrategy::applyFilter(std::shared_ptr<Packet> p) {
    return p->getProtocol().toUpper() == targetProtocol.toUpper();
}

bool PortFilterStrategy::applyFilter(std::shared_ptr<Packet> p) {
    // Простое приведение типов для проверки портов
    auto tcp = std::dynamic_pointer_cast<TcpPacket>(p);
    if (tcp) return true; // Логика проверки портов внутри TcpPacket была бы здесь

    auto udp = std::dynamic_pointer_cast<UdpPacket>(p);
    if (udp) return true;

    return false;
}
