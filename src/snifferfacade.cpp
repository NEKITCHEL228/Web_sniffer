#include "snifferfacade.h"
#include "ui.h"
#include <QDebug>

SnifferFacade::SnifferFacade(QObject *parent) : QObject(parent) {
    statistics = Statistics::getInstance();
    analyzer = std::make_unique<Analyzer>(this);
    sniffer = std::make_unique<Sniffer>(this);

    // Связываем компоненты через систему сигналов и слотов Qt (Observer Pattern)
    connect(sniffer.get(), &Sniffer::packetCaptured,
            analyzer.get(), &Analyzer::onPacketCaptured);

    // Прямая связь анализатора с UI (через родителя)
    UI* ui = qobject_cast<UI*>(parent);
    if (ui) {
        connect(analyzer.get(), &Analyzer::packetProcessed,
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
