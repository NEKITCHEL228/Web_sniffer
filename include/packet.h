#ifndef PACKET_H
#define PACKET_H

#include <QString>
#include <memory>

class Packet {
public:
    Packet(QString srcIP, QString destIP, int size, QString proto);
    virtual ~Packet() = default;

    QString getSource() const { return sourceIP; }
    QString getDestination() const { return destIP; }
    QString getProtocol() const { return protocol; }
    int getSize() const { return size; }
    QString getTime() const { return timestamp; }

    virtual QString getInfo() const = 0;

protected:
    QString sourceIP;
    QString destIP;
    QString protocol;
    QString timestamp;
    int size;
};

class TcpPacket : public Packet {
    uint16_t srcPort;
    uint16_t destPort;
public:
    TcpPacket(QString src, QString dest, int sz, uint16_t sPort, uint16_t dPort);
    QString getInfo() const override;
};

class UdpPacket : public Packet {
    uint16_t srcPort;
    uint16_t destPort;
public:
    UdpPacket(QString src, QString dest, int sz, uint16_t sPort, uint16_t dPort);
    QString getInfo() const override;
};

class IcmpPacket : public Packet {
    uint8_t type;
public:
    IcmpPacket(QString src, QString dest, int sz, uint8_t type);
    QString getInfo() const override;
};

#endif
