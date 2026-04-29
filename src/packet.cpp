#include "packet.h"
#include <QDateTime>

Packet::Packet(QString srcIP, QString destIP, int size, QString proto)
    : sourceIP(srcIP), destIP(destIP), protocol(proto), size(size)
{
    timestamp = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");
}

TcpPacket::TcpPacket(QString src, QString dest, int sz, uint16_t sPort, uint16_t dPort)
    : Packet(src, dest, sz, "TCP"), srcPort(sPort), destPort(dPort) {}

QString TcpPacket::getInfo() const {
    return QString("Ports: %1 -> %2 [TCP Sequence Data]").arg(srcPort).arg(destPort);
}

UdpPacket::UdpPacket(QString src, QString dest, int sz, uint16_t sPort, uint16_t dPort)
    : Packet(src, dest, sz, "UDP"), srcPort(sPort), destPort(dPort) {}

QString UdpPacket::getInfo() const {
    return QString("Ports: %1 -> %2 [User Datagram]").arg(srcPort).arg(destPort);
}

IcmpPacket::IcmpPacket(QString src, QString dest, int sz, uint8_t type)
    : Packet(src, dest, sz, "ICMP"), type(type) {}

QString IcmpPacket::getInfo() const {
    return QString("Type: %1 [Echo Request/Reply]").arg(type);
}
