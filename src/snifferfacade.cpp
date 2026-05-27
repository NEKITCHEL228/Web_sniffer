#include "snifferfacade.h"
#include "ui.h"
#include <QDebug>

SnifferFacade::SnifferFacade(QObject *parent) : QObject(parent) {
    statistics = Statistics::getInstance();
    sniffer = std::make_unique<Sniffer>(this);

    // Связываем компоненты через систему сигналов и слотов Qt (Observer Pattern)
    connect(sniffer.get(), &Sniffer::packetCaptured, this, [this](std::shared_ptr<Packet> packet) {
        statistics->update(packet);
        AnomalyDetector::getInstance()->update(packet);
        emit packetProcessed(packet);
    });

    // Прямая связь фасада с UI (через родителя)
    UI* ui = qobject_cast<UI*>(parent);
    if (ui) {
        connect(this, &SnifferFacade::packetProcessed,
                ui, &UI::onPacketReceived);
    }
}

void SnifferFacade::startCapture(const QString &interfaceName) {
    qDebug() << "Facade: Preparing systems for interface" << interfaceName;
    statistics->reset();
    sniffer->startCapture(interfaceName);
}

void SnifferFacade::stopCapture() {
    qDebug() << "Facade: Stopping hardware abstraction layer";
    sniffer->stopCapture();
}

void SnifferFacade::applyFilter(const QString &filterStr) {
    qDebug() << "Facade: Applying filter strategy" << filterStr;
}
