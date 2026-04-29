#ifndef PACKETFACTORY_H
#define PACKETFACTORY_H

#include "packet.h"

class PacketFactory {
public:
    static std::shared_ptr<Packet> createPacket(const unsigned char* data, int length);
};

#endif
