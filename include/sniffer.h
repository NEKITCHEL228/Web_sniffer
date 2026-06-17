#ifndef SNIFFER_H
#define SNIFFER_H

#include <QObject>
#include <memory>
#include <thread>
#include <atomic>

typedef struct pcap pcap_t;

class Packet;

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
    void packetsCapturedBatch(const std::vector<std::shared_ptr<Packet>>& packets);

private:
    void captureLoop();

    std::atomic<bool> capturing;
    pcap_t *handle;
    std::thread captureThread;
};

#endif
