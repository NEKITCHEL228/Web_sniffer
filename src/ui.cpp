#include "ui.h"
#include "sniffer.h"
#include "snifferfacade.h"
#include "filterwidget.h"
#include "packet.h"
#include "statistics.h"
#include "filemanager.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTableWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QHeaderView>
#include <QIcon>
#include <QApplication>
#include <QDebug>
#include <QFileDialog>

UI::UI(QWidget *parent) : QMainWindow(parent) {
    facade = std::make_unique<SnifferFacade>(this);
    setupUI();
    applyStyles();
    onRefreshInterfaces();
}

UI::~UI() {}

void UI::setupUI() {
    auto *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    auto *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(24, 24, 24, 24);
    mainLayout->setSpacing(24);

    // Top Panel
    auto *topPanel = new QHBoxLayout();
    topPanel->setSpacing(12);

    comboInterface = new QComboBox(this);
    comboInterface->setMinimumWidth(300);
    comboInterface->setFixedHeight(44);
    topPanel->addWidget(comboInterface);

    btnClearTable = new QPushButton(this);
    btnClearTable->setFixedSize(44, 44);
    btnClearTable->setToolTip("Очистить таблицу");
    btnClearTable->setIcon(QIcon(":/icons/Clear.svg"));
    topPanel->addWidget(btnClearTable);

    filterInput = new QLineEdit(this);
    filterInput->setPlaceholderText("tcp.port == 443 and ip.addr == 192.168.1.1");
    filterInput->setFixedHeight(44);
    topPanel->addWidget(filterInput, 1);

    auto *btnFilter = new QPushButton(this);
    btnFilter->setFixedSize(44, 44);
    btnFilter->setIcon(QIcon(":/icons/Filter.svg"));
    topPanel->addWidget(btnFilter);

    btnStart = new QPushButton(this);
    btnStart->setFixedHeight(44);
    btnStart->setMinimumWidth(120);
    setupButtonContent(btnStart, "НАЧАТЬ", ":/icons/Start.svg");
    topPanel->addWidget(btnStart);

    btnStop = new QPushButton(this);
    btnStop->setFixedHeight(44);
    btnStop->setMinimumWidth(120);
    setupButtonContent(btnStop, "СТОП", ":/icons/Stop.svg");
    btnStop->hide();
    topPanel->addWidget(btnStop);

    filterWidget = new FilterWidget(this);
    // FilterWidget floats over the main window, so we don't add it to mainLayout
    filterWidget->hide();
    connect(filterWidget, &FilterWidget::filtersApplied, this, &UI::applySimpleFilter);

    mainLayout->addLayout(topPanel);

    // Table
    packetTable = new QTableWidget(0, 5, this);
    packetTable->setHorizontalHeaderLabels({"ВРЕМЯ", "ПРОТОКОЛ", "ОТПРАВИТЕЛЬ", "ПОЛУЧАТЕЛЬ", "ИНФОРМАЦИЯ"});
    packetTable->horizontalHeader()->setStretchLastSection(true);
    packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    packetTable->setAlternatingRowColors(false);
    packetTable->setShowGrid(false);
    packetTable->verticalHeader()->setVisible(false);
    mainLayout->addWidget(packetTable);

    // Bottom Panel
    auto *bottomPanel = new QHBoxLayout();
    lblStatistics = new QLabel("Захвачено: 0 | Отображается: 0", this);
    lblStatistics->setStyleSheet("color: #94A3B8; font-size: 14px;");
    bottomPanel->addWidget(lblStatistics);

    auto *btnUpload = new QPushButton(this);
    setupButtonContent(btnUpload, "ЗАГРУЗИТЬ", ":/icons/Upload.svg");
    auto *btnDownload = new QPushButton(this);
    setupButtonContent(btnDownload, "СКАЧАТЬ", ":/icons/Download.svg");
    btnUpload->setObjectName("btnUpload");
    btnDownload->setObjectName("btnDownload");
    btnUpload->setFixedSize(160, 48);
    btnDownload->setFixedSize(160, 48);
    bottomPanel->addStretch();
    bottomPanel->addWidget(btnUpload);
    bottomPanel->addWidget(btnDownload);
    mainLayout->addLayout(bottomPanel);

    // Connections
    connect(btnStart, &QPushButton::clicked, this, &UI::onStartClicked);
    connect(btnStop, &QPushButton::clicked, this, &UI::onStopClicked);
    connect(btnClearTable, &QPushButton::clicked, this, [this]() {
        packetTable->setRowCount(0);
        allPackets.clear();
        Statistics::getInstance()->reset();
        updateStatistics();
    });
    connect(btnFilter, &QPushButton::clicked, this, [this]() {
        if (!filterWidget->isVisible()) {
            filterWidget->adjustSize();
            QPoint pos = filterInput->mapTo(this, QPoint(0, filterInput->height()));
            pos.setY(pos.y() + 8);
            filterWidget->move(pos);
            filterWidget->raise();
            filterWidget->show();
        } else {
            filterWidget->hide();
        }
    });

    connect(btnDownload, &QPushButton::clicked, this, [this]() {
        QString filename = QFileDialog::getSaveFileName(this, "Сохранить PCAP", "", "PCAP Files (*.pcap)");
        if (!filename.isEmpty()) {
            FileManager::getInstance()->saveToPcap(filename, allPackets);
        }
    });

    connect(btnUpload, &QPushButton::clicked, this, [this]() {
        QString filename = QFileDialog::getOpenFileName(this, "Загрузить PCAP", "", "PCAP Files (*.pcap)");
        if (!filename.isEmpty()) {
            auto packets = FileManager::getInstance()->loadFromPcap(filename);
            packetTable->setRowCount(0);
            allPackets.clear();
            Statistics::getInstance()->reset();

            for (auto p : packets) {
                allPackets.push_back(p);
                Statistics::getInstance()->update(p);
                if (isPacketMatching(p)) {
                    addPacketToTable(p);
                }
            }
            updateStatistics();
        }
    });

    connect(filterInput, &QLineEdit::returnPressed, this, &UI::applyStringFilter);
    connect(filterInput, &QLineEdit::textChanged, this, [this](const QString &text) {
        if (text.trimmed().isEmpty()) {
            applyStringFilter();
        }
    });

    resize(1184, 768);
    setWindowTitle("Web Sniffer - QTSniffer Engine");
}

void UI::onRefreshInterfaces() {
    comboInterface->clear();
    comboInterface->addItem("Выберите сетевой интерфейс", "");
    auto interfaces = Sniffer::getAvailableInterfaces();
    for (const auto &iface : interfaces) {
        comboInterface->addItem(iface.description, iface.name);
    }
}

void UI::onStartClicked() {
    QString iface = comboInterface->currentData().toString();
    if (iface.isEmpty()) {
        comboInterface->setStyleSheet("QComboBox { border: 1px solid #EAB308; background: #454726; }");
        return;
    }
    comboInterface->setStyleSheet("");
    comboInterface->setEnabled(false);
    btnStart->hide();
    btnStop->show();

    if (iface != lastInterface) {
        packetTable->setRowCount(0);
        allPackets.clear();
        lastInterface = iface;
        updateStatistics();
    }

    facade->startCapture(iface);
}

void UI::onStopClicked() {
    comboInterface->setEnabled(true);
    btnStart->show();
    btnStop->hide();
    facade->stopCapture();
}

void UI::onPacketReceived(std::shared_ptr<Packet> packet) {
    allPackets.push_back(packet);
    if (isPacketMatching(packet)) {
        addPacketToTable(packet);
    }
    updateStatistics();
}

void UI::addPacketToTable(std::shared_ptr<Packet> packet) {
    int row = packetTable->rowCount();
    packetTable->insertRow(row);

    auto *timeItem = new QTableWidgetItem(packet->getTime());
    timeItem->setTextAlignment(Qt::AlignCenter);
    packetTable->setItem(row, 0, timeItem);

    auto *protoItem = new QTableWidgetItem(packet->getProtocol());
    protoItem->setTextAlignment(Qt::AlignCenter);
    packetTable->setItem(row, 1, protoItem);

    auto *srcItem = new QTableWidgetItem(packet->getSource());
    srcItem->setTextAlignment(Qt::AlignCenter);
    packetTable->setItem(row, 2, srcItem);

    auto *destItem = new QTableWidgetItem(packet->getDestination());
    destItem->setTextAlignment(Qt::AlignCenter);
    packetTable->setItem(row, 3, destItem);

    auto *infoItem = new QTableWidgetItem(packet->getInfo());
    infoItem->setTextAlignment(Qt::AlignCenter);
    packetTable->setItem(row, 4, infoItem);

    packetTable->scrollToBottom();
}

void UI::setupButtonContent(QPushButton* btn, const QString& text, const QString& iconPath) {
    btn->setText(text);
    btn->setIcon(QIcon(iconPath));
    btn->setIconSize(QSize(20, 20));
}

void UI::applyStyles() {
    this->setStyleSheet(R"(
        QMainWindow { background-color: #0F172A; }
        QComboBox { background-color: #1E293B; border: 1px solid #334155; border-radius: 8px; color: #F8FAFC; padding: 0 12px; font-size: 13px; }
        QComboBox::drop-down { border: none; }
        QLineEdit { background-color: #1E293B; border: 1px solid #334155; border-radius: 8px; color: #F8FAFC; padding: 0 12px; font-size: 13px; }
        QPushButton { border-radius: 8px; font-weight: bold; font-size: 12px; letter-spacing: 1px; color: white; border: 1px solid #334155; background: #1E293B; }
        QPushButton:hover { background-color: #334155; }
        QPushButton#btnStart { background-color: #22C55E; border: none; }
        QPushButton#btnStop { background-color: #EF4444; border: none; }
        QPushButton#btnUpload { background-color: #3B82F6; border: none; }
        QPushButton#btnDownload { background-color: #22C55E; border: none; }
        QTableWidget { background-color: #1E293B; border: 1px solid #334155; border-radius: 12px; color: #F8FAFC; gridline-color: transparent; selection-background-color: #334155; }
        QHeaderView::section { background-color: #1E293B; color: #94A3B8; padding: 12px; border: none; border-bottom: 2px solid #334155; font-weight: bold; font-size: 11px; }
        QTableWidget::item { padding: 12px; border-bottom: 1px solid #334155; font-family: 'JetBrains Mono'; font-size: 12px; }
    )");
}

void UI::onInterfaceChanged() {}

bool UI::isPacketMatching(std::shared_ptr<Packet> packet) {
    if (currentFilter.ipActive && !currentFilter.ip.isEmpty()) {
        if (packet->getDestination() != currentFilter.ip) {
            return false;
        }
    }

    if (currentFilter.srcIpActive && !currentFilter.srcIp.isEmpty()) {
        if (packet->getSource() != currentFilter.srcIp) {
            return false;
        }
    }

    if (currentFilter.protoActive && !currentFilter.proto.isEmpty()) {
        if (packet->getProtocol().compare(currentFilter.proto, Qt::CaseInsensitive) != 0) {
            return false;
        }
    }

    if (currentFilter.portActive && !currentFilter.port.isEmpty()) {
        bool ok;
        uint16_t targetPort = currentFilter.port.toUShort(&ok);
        if (ok) {
            uint16_t srcPort = packet->getSrcPort();
            uint16_t destPort = packet->getDestPort();
            if (srcPort != targetPort && destPort != targetPort) {
                return false;
            }
        }
    }

    if (currentStringFilter) {
        if (!currentStringFilter->evaluate(packet)) {
            return false;
        }
    }

    return true;
}

void UI::applyStringFilter() {
    QString query = filterInput->text();
    if (query.trimmed().isEmpty()) {
        currentStringFilter = nullptr;
    } else {
        currentStringFilter = FilterParser::parse(query);
        if (!currentStringFilter) {
            // Option to show error to user in UI if parsing fails
            qDebug() << "Failed to parse filter query";
        }
    }
    redrawTable();
}

void UI::applySimpleFilter(SimpleFilterData data) {
    currentFilter = data;
    redrawTable();
}

void UI::redrawTable() {
    packetTable->setRowCount(0);
    for (const auto& packet : allPackets) {
        if (isPacketMatching(packet)) {
            addPacketToTable(packet);
        }
    }
    updateStatistics();
}

void UI::updateStatistics() {
    int total = Statistics::getInstance()->getTotalPackets();
    int displayed = packetTable->rowCount();
    long long volume = Statistics::getInstance()->getTotalVolume();
    lblStatistics->setText(QString("Захвачено: %1 | Отображается: %2 | Общий объем: %3 байт").arg(total).arg(displayed).arg(volume));
}
