#ifndef SNIFFERFACADE_H
#define SNIFFERFACADE_H

#include <QObject>
#include <memory>
#include "statistics.h"
#include "anomalydetector.h"
#include "sniffer.h"

enum class AnalysisCategory;

class SnifferFacade : public QObject {
    Q_OBJECT
public:
    explicit SnifferFacade(QObject *parent = nullptr);
    void startCapture(const QString &interfaceName);
    void stopCapture();
    void applyFilter(const QString &filterStr);

signals:
    void packetProcessed(std::shared_ptr<Packet> packet);
    void packetsProcessedBatch(const PacketList& packets);

private:
    Statistics *statistics;
    std::unique_ptr<Sniffer> sniffer;
};

#endif
