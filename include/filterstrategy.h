#ifndef FILTERSTRATEGY_H
#define FILTERSTRATEGY_H

#include "packet.h"

class IFilterStrategy {
public:
    virtual ~IFilterStrategy() = default;
    virtual bool applyFilter(std::shared_ptr<Packet> p) = 0;
};

class IpFilterStrategy : public IFilterStrategy {
    QString targetIp;
public:
    IpFilterStrategy(QString ip) : targetIp(ip) {}
    bool applyFilter(std::shared_ptr<Packet> p) override;
};

class ProtocolFilterStrategy : public IFilterStrategy {
    QString targetProtocol;
public:
    ProtocolFilterStrategy(QString proto) : targetProtocol(proto) {}
    bool applyFilter(std::shared_ptr<Packet> p) override;
};

class PortFilterStrategy : public IFilterStrategy {
    uint16_t targetPort;
public:
    PortFilterStrategy(uint16_t port) : targetPort(port) {}
    bool applyFilter(std::shared_ptr<Packet> p) override;
};

#endif
