#ifndef ANALYZER_H
#define ANALYZER_H

#include "packet.h"
#include "filterstrategy.h"
#include <QObject>
#include <memory>

class Analyzer : public QObject {
    Q_OBJECT
public:
    explicit Analyzer(QObject *parent = nullptr);
    void setFilterStrategy(std::shared_ptr<IFilterStrategy> strategy) { currentStrategy = strategy; }

public slots:
    void onPacketCaptured(std::shared_ptr<Packet> packet);

signals:
    void packetProcessed(std::shared_ptr<Packet> packet);

private:
    std::shared_ptr<IFilterStrategy> currentStrategy;
};

#endif
