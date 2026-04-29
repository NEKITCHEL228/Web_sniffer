#ifndef SNIFFER_H
#define SNIFFER_H

#include <QObject>
#include <memory>

class Packet;

struct InterfaceInfo {
    QString name;
    QString description;
};

class Sniffer : public QObject {
    Q_OBJECT
public:
    explicit Sniffer(QObject *parent = nullptr);
    static std::vector<InterfaceInfo> getAvailableInterfaces();

    void startCapture(const QString &interfaceName);
    void stopCapture();

signals:
    void packetCaptured(std::shared_ptr<Packet> packet);

private:
    bool capturing;
};

#endif
