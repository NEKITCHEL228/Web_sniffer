#ifndef SNIFFER_H
#define SNIFFER_H

#include <QObject>
#include <QString>
#include <QMetaType>
#include <memory>
#include <vector>
#include <thread>
#include <atomic>
#include "packet.h"

typedef struct pcap pcap_t;

Q_DECLARE_METATYPE(PacketList)

struct InterfaceInfo {
    QString name;
    QString description;
};

class Sniffer : public QObject {
    Q_OBJECT
public:
    explicit Sniffer(QObject *parent = nullptr);
    ~Sniffer() override;
    static std::vector<InterfaceInfo> getAvailableInterfaces();

    void startCapture(const QString &interfaceName);
    void stopCapture();

signals:
    void packetCaptured(std::shared_ptr<Packet> packet);
    void packetsCapturedBatch(const PacketList& packets);

private:
    void captureLoop();

    std::atomic<bool> capturing;
    pcap_t *handle;
    std::thread captureThread;
};

#endif
