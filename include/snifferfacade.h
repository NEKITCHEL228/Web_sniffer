#ifndef SNIFFERFACADE_H
#define SNIFFERFACADE_H

#include <QObject>
#include <memory>
#include "statistics.h"
#include "analyzer.h"
#include "sniffer.h"

class SnifferFacade : public QObject {
    Q_OBJECT
public:
    explicit SnifferFacade(QObject *parent = nullptr);
    void startCapture(const QString &interfaceName);
    void stopCapture();
    void applyFilter(const QString &filterStr);

private:
    Statistics *statistics;
    std::unique_ptr<Analyzer> analyzer;
    std::unique_ptr<Sniffer> sniffer;
};

#endif
