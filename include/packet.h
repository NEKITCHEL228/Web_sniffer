#ifndef PACKET_H
#define PACKET_H

#include <QString>
#include <memory>
#include <vector>

class Packet {
public:
    Packet(QString srcIP, QString destIP, int size, QString proto);
    virtual ~Packet() = default;

    QString getSource() const { return sourceIP; }
    QString getDestination() const { return destIP; }
    QString getProtocol() const { return protocol; }
    int getSize() const { return size; }
    QString getTime() const { return timestamp; }
    virtual int getSrcPort() const = 0;
    virtual int getDestPort() const = 0;

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
    int srcPort;
    int destPort;
public:
    TcpPacket(QString src, QString dest, int sz, int sPort, int dPort);
    int getSrcPort() const override { return srcPort; }
    int getDestPort() const override { return destPort; }
    QString getInfo() const override;
};

class UdpPacket : public Packet {
    int srcPort;
    int destPort;
public:
    UdpPacket(QString src, QString dest, int sz, int sPort, int dPort);
    int getSrcPort() const override { return srcPort; }
    int getDestPort() const override { return destPort; }
    QString getInfo() const override;
};

class IcmpPacket : public Packet {
    int type;
public:
    IcmpPacket(QString src, QString dest, int sz, int type);
    int getSrcPort() const override { return 0; }
    int getDestPort() const override { return 0; }
    QString getInfo() const override;
};

#endif
