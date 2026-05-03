#include "filemanager.h"
#include "packetfactory.h"
#include <QFile>
#include <QHostAddress>
#include <QDateTime>
#include <QtEndian>
#include <pcap.h>

FileManager* FileManager::instance = nullptr;

FileManager* FileManager::getInstance() {
    if (!instance) instance = new FileManager();
    return instance;
}

bool FileManager::saveToPcap(const QString &filename, const std::vector<std::shared_ptr<Packet>> &packets) {
    pcap_t* pd = pcap_open_dead(1, 65535); // 1 = DLT_EN10MB
    if (!pd) return false;

    pcap_dumper_t* pdumper = pcap_dump_open(pd, filename.toUtf8().constData());
    if (!pdumper) {
        pcap_close(pd);
        return false;
    }

    for (const auto& packet : packets) {
        struct pcap_pkthdr hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.ts.tv_sec = QDateTime::currentSecsSinceEpoch();
        hdr.ts.tv_usec = 0;

        int pkt_len = packet->getSize();
        int actual_len = std::min(pkt_len, 65535);
        // fallback headers minimum
        if (actual_len < 54) actual_len = 54;

        hdr.len = pkt_len;
        hdr.caplen = actual_len;

        std::vector<unsigned char> data(actual_len, 0);

        // Ethernet Header (14 bytes)
        data[12] = 0x08; data[13] = 0x00; // IPv4

        // IP Header (20 bytes)
        data[14] = 0x45; // Version 4, IHL 5
        data[22] = 64; // TTL

        if (packet->getProtocol() == "TCP") data[23] = 6;
        else if (packet->getProtocol() == "UDP") data[23] = 17;
        else if (packet->getProtocol() == "ICMP") data[23] = 1;

        QHostAddress srcAddr(packet->getSource());
        QHostAddress dstAddr(packet->getDestination());
        uint32_t srcIp = qToBigEndian(srcAddr.toIPv4Address());
        uint32_t dstIp = qToBigEndian(dstAddr.toIPv4Address());
        memcpy(&data[26], &srcIp, 4);
        memcpy(&data[30], &dstIp, 4);

        // TCP / UDP Header
        if (packet->getProtocol() == "TCP") {
            uint16_t srcPort = qToBigEndian(packet->getSrcPort());
            uint16_t dstPort = qToBigEndian(packet->getDestPort());
            memcpy(&data[34], &srcPort, 2);
            memcpy(&data[36], &dstPort, 2);
            data[46] = 0x50; // Data offset 5
        } else if (packet->getProtocol() == "UDP") {
            uint16_t srcPort = qToBigEndian(packet->getSrcPort());
            uint16_t dstPort = qToBigEndian(packet->getDestPort());
            memcpy(&data[34], &srcPort, 2);
            memcpy(&data[36], &dstPort, 2);
            uint16_t ulen = qToBigEndian((uint16_t)8); // min length
            memcpy(&data[38], &ulen, 2);
        } else if (packet->getProtocol() == "ICMP") {
            data[34] = 8; // Default Echo Request
        }

        pcap_dump((u_char*)pdumper, &hdr, data.data());
    }

    pcap_dump_close(pdumper);
    pcap_close(pd);
    return true;
}

std::vector<std::shared_ptr<Packet>> FileManager::loadFromPcap(const QString &filename) {
    std::vector<std::shared_ptr<Packet>> packets;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename.toUtf8().constData(), errbuf);

    if (handle == nullptr) {
        return packets;
    }

    struct pcap_pkthdr *header;
    const u_char *pkt_data;

    while (pcap_next_ex(handle, &header, &pkt_data) >= 0) {
        std::shared_ptr<Packet> pInfo = PacketFactory::createPacket(pkt_data, header->caplen);
        if (pInfo != nullptr) {
            packets.push_back(pInfo);
        }
    }

    pcap_close(handle);
    return packets;
}
