#ifndef PACKET_H
#define PACKET_H

#include <QString>
#include <cstdint>
#include <vector>

class Packet;
typedef std::vector<std::shared_ptr<Packet>> PacketList;

class Packet {
public:
    Packet(const QString& srcIP, const QString& destIP, int size, const QString& proto);
    virtual ~Packet() = default;

    QString getSource() const { return sourceIP; }
    QString getDestination() const { return destIP; }
    QString getProtocol() const { return protocol; }
    int getSize() const { return size; }
    QString getTime() const { return timestamp; }
    virtual uint16_t getSrcPort() const { return 0; }
    virtual uint16_t getDestPort() const { return 0; }

    virtual QString getInfo() const = 0;

    void setRawData(const std::vector<uint8_t>& data) { rawData = data; }
    const std::vector<uint8_t>& getRawData() const { return rawData; }

protected:
    QString sourceIP;
    QString destIP;
    QString protocol;
    QString timestamp;
    int size;
    std::vector<uint8_t> rawData;
};

class TcpPacket : public Packet {
    uint16_t srcPort;
    uint16_t destPort;
public:
    TcpPacket(const QString& src, const QString& dest, int sz, uint16_t sPort, uint16_t dPort);
    uint16_t getSrcPort() const override { return srcPort; }
    uint16_t getDestPort() const override { return destPort; }
    QString getInfo() const override;
};

class UdpPacket : public Packet {
    uint16_t srcPort;
    uint16_t destPort;
public:
    UdpPacket(const QString& src, const QString& dest, int sz, uint16_t sPort, uint16_t dPort);
    uint16_t getSrcPort() const override { return srcPort; }
    uint16_t getDestPort() const override { return destPort; }
    QString getInfo() const override;
};

class IcmpPacket : public Packet {
    uint8_t type;
public:
    IcmpPacket(const QString& src, const QString& dest, int sz, uint8_t type);
    QString getInfo() const override;
};

#endif
