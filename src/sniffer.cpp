#include "sniffer.h"
#include <pcap.h>
#include <QDebug>

Sniffer::Sniffer(QObject *parent) : QObject(parent), capturing(false) {}

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
    capturing = true;
    qDebug() << "Sniffer: Start capture on" << interfaceName;
    // В реальном приложении здесь запускается pcap_loop в отдельном потоке
}

void Sniffer::stopCapture() {
    capturing = false;
    qDebug() << "Sniffer: Stop capture";
}
