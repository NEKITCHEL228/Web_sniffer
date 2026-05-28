#include "packet.h"
#include <QDateTime>

// Recompile force trigger

Packet::Packet(const QString& srcIP, const QString& destIP, int size, const QString& proto)
    : sourceIP(srcIP), destIP(destIP), protocol(proto), size(size)
{
    timestamp = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");
}

TcpPacket::TcpPacket(const QString& src, const QString& dest, int sz, uint16_t sPort, uint16_t dPort)
    : Packet(src, dest, sz, "TCP"), srcPort(sPort), destPort(dPort) {}

QString TcpPacket::getInfo() const {
    return QString("Ports: %1 -> %2 [TCP Sequence Data]").arg(srcPort).arg(destPort);
}

UdpPacket::UdpPacket(const QString& src, const QString& dest, int sz, uint16_t sPort, uint16_t dPort)
    : Packet(src, dest, sz, "UDP"), srcPort(sPort), destPort(dPort) {}

QString UdpPacket::getInfo() const {
    return QString("Ports: %1 -> %2 [User Datagram]").arg(srcPort).arg(destPort);
}

IcmpPacket::IcmpPacket(const QString& src, const QString& dest, int sz, uint8_t type)
    : Packet(src, dest, sz, "ICMP"), type(type) {}

QString IcmpPacket::getInfo() const {
    return QString("Type: %1 [Echo Request/Reply]").arg(type);
}
