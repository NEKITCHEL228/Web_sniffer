#include "packetfactory.h"

std::shared_ptr<Packet> PacketFactory::createPacket(const unsigned char* data, int length) {
    if (length < 34) return nullptr; // Минимальный размер заголовков

    int protocolType = data[23];
    QString srcIP = QString("%1.%2.%3.%4").arg(data[26]).arg(data[27]).arg(data[28]).arg(data[29]);
    QString destIP = QString("%1.%2.%3.%4").arg(data[30]).arg(data[31]).arg(data[32]).arg(data[33]);

    if (protocolType == 6) { // TCP
        uint16_t sp = (data[34] << 8) | data[35];
        uint16_t dp = (data[36] << 8) | data[37];
        return std::make_shared<TcpPacket>(srcIP, destIP, length, sp, dp);
    } else if (protocolType == 17) { // UDP
        uint16_t sp = (data[34] << 8) | data[35];
        uint16_t dp = (data[36] << 8) | data[37];
        return std::make_shared<UdpPacket>(srcIP, destIP, length, sp, dp);
    } else if (protocolType == 1) { // ICMP
        return std::make_shared<IcmpPacket>(srcIP, destIP, length, data[34]);
    }
    return nullptr;
}
