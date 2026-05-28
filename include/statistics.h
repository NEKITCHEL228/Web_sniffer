#ifndef STATISTICS_H
#define STATISTICS_H

#include "packet.h"
#include <QMap>
#include <QStringList>

class Statistics {
public:
    static Statistics* getInstance();
    void update(std::shared_ptr<Packet> p);
    void reset();

    int getTotalPackets() const { return totalPackets; }
    long long getTotalVolume() const { return totalVolume; }
    QMap<QString, int> getProtocolStats() const { return protocolStats; }

    int getEncryptedPackets() const { return encryptedPackets; }
    int getUnencryptedPackets() const { return unencryptedPackets; }
    int getDnsQueries() const { return dnsQueries; }

    bool isEncrypted(const std::shared_ptr<Packet>& p) const;
    bool isUnencrypted(const std::shared_ptr<Packet>& p) const;
    bool isDNS(const std::shared_ptr<Packet>& p) const;

private:
    Statistics() : totalPackets(0), totalVolume(0), encryptedPackets(0), unencryptedPackets(0), dnsQueries(0) {}
    static Statistics* instance;

    int totalPackets;
    long long totalVolume;
    QMap<QString, int> protocolStats;

    int encryptedPackets;
    int unencryptedPackets;
    int dnsQueries;
};

#endif
