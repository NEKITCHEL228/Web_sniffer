#include "sniffer.h"
#include "packetfactory.h"
#include "packet.h"
#include <pcap.h>
#include <QDebug>
#include <QMetaType>
#include <QCoreApplication>

Sniffer::Sniffer(QObject *parent) : QObject(parent), capturing(false), handle(nullptr) {
    qRegisterMetaType<std::shared_ptr<Packet>>("std::shared_ptr<Packet>");
    qRegisterMetaType<std::vector<std::shared_ptr<Packet>>>("std::vector<std::shared_ptr<Packet>>");
}

Sniffer::~Sniffer() {
    stopCapture();
}

std::vector<InterfaceInfo> Sniffer::getAvailableInterfaces() {
    std::vector<InterfaceInfo> interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    qDebug() << "Sniffer: Using library version:" << pcap_lib_version();
    qDebug() << "Sniffer: Searching for interfaces...";

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qCritical() << "Sniffer: Error in pcap_findalldevs:" << errbuf;
        return interfaces;
    }

    if (alldevs == nullptr) {
        qWarning() << "Sniffer: No interfaces found. Check Npcap/WinPcap service and Admin rights.";
    }

    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        InterfaceInfo info;
        // На Windows d->name это обычно GUID (\Device\NPF_...)
        info.name = QString::fromUtf8(d->name);
        info.description = d->description ? QString::fromLocal8Bit(d->description) : info.name;

        qDebug() << "Found interface:" << info.name;
        if (d->description) qDebug() << "   Description:" << info.description;

        interfaces.push_back(info);
    }

    pcap_freealldevs(alldevs);
    return interfaces;
}

void Sniffer::startCapture(const QString &interfaceName) {
    if (capturing) {
        qWarning() << "Sniffer: Already capturing.";
        return;
    }

    qDebug() << "Sniffer: Start capture on" << interfaceName;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the adapter
    handle = pcap_open_live(interfaceName.toUtf8().constData(), 65536, 1, 1000, errbuf);

    if (handle == nullptr) {
        qCritical() << "Sniffer: Unable to open the adapter." << interfaceName << "is not supported by Npcap/WinPcap. Error:" << errbuf;
        return;
    }

    capturing = true;
    captureThread = std::thread(&Sniffer::captureLoop, this);
}

void Sniffer::stopCapture() {
    if (!capturing) return;

    qDebug() << "Sniffer: Stop capture";
    capturing = false;

    if (handle != nullptr) {
        pcap_breakloop(handle);
    }

    if (captureThread.joinable()) {
        captureThread.join();
    }

    if (handle != nullptr) {
        pcap_close(handle);
        handle = nullptr;
    }
}

void Sniffer::captureLoop() {
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res;

    std::vector<std::shared_ptr<Packet>> batch;
    batch.reserve(256);
    auto lastEmitTime = std::chrono::steady_clock::now();

    while (capturing && (res = pcap_next_ex(handle, &header, &pkt_data)) >= 0) {
        if (res == 0) {
            // Timeout elapsed, flush batch
            if (!batch.empty()) {
                emit packetsCapturedBatch(batch);
                batch.clear();
            }
            continue;
        }

        if (capturing) {
            std::shared_ptr<Packet> pInfo = PacketFactory::createPacket(pkt_data, header->caplen);
            if (pInfo != nullptr) {
                batch.push_back(pInfo);

                auto now = std::chrono::steady_clock::now();
                if (batch.size() >= 256 || std::chrono::duration_cast<std::chrono::milliseconds>(now - lastEmitTime).count() > 50) {
                    emit packetsCapturedBatch(batch);
                    batch.clear();
                    lastEmitTime = now;
                }
            }
        }
    }

    // final flush
    if (!batch.empty() && capturing) {
        emit packetsCapturedBatch(batch);
    }
}
