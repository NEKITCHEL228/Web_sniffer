#include "ui.h"
#include "sniffer.h"
#include "snifferfacade.h"
#include "filterwidget.h"
#include "packet.h"
#include "statistics.h"
#include "anomalydetector.h"
#include "filemanager.h"
#include <QTextEdit>
#include <QStackedWidget>
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
#include <QWidget>
#include <QTimer>

UI::UI(QWidget *parent) : QMainWindow(parent) {
    facade = std::make_unique<SnifferFacade>(this);
    setupUI();
    applyStyles();
    onRefreshInterfaces();
    showCaptureView(); // Set initial view

    updateTimer = new QTimer(this);
    connect(updateTimer, &QTimer::timeout, this, &UI::processPendingPackets);
    updateTimer->start(100);
}

UI::~UI() {}

void UI::setupUI() {
    auto *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    auto *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    // Top Navigation Panel
    auto *topNavPanel = new QWidget(this);
    topNavPanel->setObjectName("topNavPanel");
    topNavPanel->setStyleSheet("QWidget#topNavPanel { background-color: #1E293B; border-bottom: 1px solid #334155; }");
    auto *topNavLayout = new QHBoxLayout(topNavPanel);
    topNavLayout->setContentsMargins(24, 12, 24, 12);
    topNavLayout->setSpacing(12);

    btnNavCapture = new QPushButton("Захват", this);
    btnNavAnalysis = new QPushButton("Анализ", this);
    btnNavCapture->setObjectName("btnNavCapture");
    btnNavAnalysis->setObjectName("btnNavAnalysis");
    btnNavCapture->setFixedSize(120, 36);
    btnNavAnalysis->setFixedSize(120, 36);
    btnNavCapture->setCursor(Qt::PointingHandCursor);
    btnNavAnalysis->setCursor(Qt::PointingHandCursor);

    topNavLayout->addWidget(btnNavCapture);
    topNavLayout->addWidget(btnNavAnalysis);
    topNavLayout->addStretch();
    mainLayout->addWidget(topNavPanel);

    stackedWidget = new QStackedWidget(this);
    mainLayout->addWidget(stackedWidget);

    // ---- Capture View ----
    captureWidget = new QWidget(this);
    auto *captureLayout = new QVBoxLayout(captureWidget);
    captureLayout->setContentsMargins(24, 24, 24, 24);
    captureLayout->setSpacing(24);
    stackedWidget->addWidget(captureWidget);

    // ---- Analysis View ----
    analysisWidget = new QWidget(this);
    auto *analysisMainLayout = new QVBoxLayout(analysisWidget);
    analysisMainLayout->setContentsMargins(0, 0, 0, 0);

    analysisStackedWidget = new QStackedWidget(analysisWidget);
    analysisMainLayout->addWidget(analysisStackedWidget);

    // Analysis Dashboard
    analysisDashboard = new QWidget(analysisStackedWidget);
    analysisDashboardLayout = new QVBoxLayout(analysisDashboard);
    analysisDashboardLayout->setContentsMargins(24, 24, 24, 24);
    analysisDashboardLayout->setSpacing(24);

    // We will populate dashboard inside showAnalysisView or updateAnalysisDashboard
    // For now, put a placeholder or just layout stretch
    analysisDashboardLayout->addStretch();

    analysisStackedWidget->addWidget(analysisDashboard);

    // Analysis Table Container
    analysisTableContainer = new QWidget(analysisStackedWidget);
    auto *analysisTableLayout = new QVBoxLayout(analysisTableContainer);
    analysisTableLayout->setContentsMargins(24, 24, 24, 24);
    analysisTableLayout->setSpacing(24);

    auto *btnBackToDashboard = new QPushButton("Назад к статистике", analysisTableContainer);
    btnBackToDashboard->setFixedSize(160, 36);
    btnBackToDashboard->setCursor(Qt::PointingHandCursor);
    connect(btnBackToDashboard, &QPushButton::clicked, this, &UI::showAnalysisDashboard);

    analysisTable = new QTableWidget(0, 5, analysisTableContainer);
    analysisTable->setHorizontalHeaderLabels({"№", "Время", "Источник", "Цель", "Протокол"});
    analysisTable->horizontalHeader()->setStretchLastSection(true);
    analysisTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    analysisTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    analysisTable->setAlternatingRowColors(false);
    analysisTable->setShowGrid(true);
    analysisTable->verticalHeader()->setVisible(false);
    analysisTable->setFocusPolicy(Qt::NoFocus);

    connect(analysisTable, &QTableWidget::cellDoubleClicked, this, &UI::onAnalysisTableDoubleClicked);

    analysisTableLayout->addWidget(btnBackToDashboard);
    analysisTableLayout->addWidget(analysisTable);

    analysisStackedWidget->addWidget(analysisTableContainer);
    stackedWidget->addWidget(analysisWidget);

    // ---- Packet Details View ----
    packetDetailsWidget = new QWidget(this);
    auto *detailsLayout = new QVBoxLayout(packetDetailsWidget);
    detailsLayout->setContentsMargins(24, 24, 24, 24);
    detailsLayout->setSpacing(24);

    auto *btnBackToCapture = new QPushButton("Назад", packetDetailsWidget);
    btnBackToCapture->setFixedSize(160, 36);
    btnBackToCapture->setCursor(Qt::PointingHandCursor);
    connect(btnBackToCapture, &QPushButton::clicked, this, &UI::backFromPacketDetails);

    lblDetailSummary = new QLabel(packetDetailsWidget);
    lblDetailSummary->setStyleSheet("color: white; font-size: 16px; font-weight: bold;");

    textRawData = new QTextEdit(packetDetailsWidget);
    textRawData->setReadOnly(true);
    textRawData->setStyleSheet("QTextEdit { background-color: #1E293B; color: #F8FAFC; border: 1px solid #334155; border-radius: 8px; font-family: 'JetBrains Mono'; padding: 12px; }");

    detailsLayout->addWidget(btnBackToCapture);
    detailsLayout->addWidget(lblDetailSummary);

    auto *lblDetailsTitle = new QLabel("Подробная информация о пакете", packetDetailsWidget);
    lblDetailsTitle->setAlignment(Qt::AlignCenter);
    lblDetailsTitle->setStyleSheet("color: white; font-size: 18px; font-weight: bold; margin-top: 10px; margin-bottom: 5px;");
    detailsLayout->addWidget(lblDetailsTitle);

    detailsLayout->addWidget(textRawData);
    stackedWidget->addWidget(packetDetailsWidget);

    // Top Panel for Capture View
    auto *topPanel = new QHBoxLayout();
    topPanel->setSpacing(12);

    comboInterface = new QComboBox(this);
    comboInterface->setMinimumWidth(300);
    comboInterface->setFixedHeight(44);
    comboInterface->setMaxVisibleItems(10);
    topPanel->addWidget(comboInterface);

    btnClearTable = new QPushButton(this);
    btnClearTable->setFixedSize(44, 44);
    btnClearTable->setToolTip("Очистить таблицу");
    btnClearTable->setIcon(QIcon(":/icons/Clear.svg"));
    btnClearTable->setIconSize(QSize(24, 24));
    topPanel->addWidget(btnClearTable);

    filterInput = new QLineEdit(this);
    filterInput->setPlaceholderText("tcp.port == 443 and ip.addr == 192.168.1.1");
    filterInput->setFixedHeight(44);
    topPanel->addWidget(filterInput, 1);

    auto *btnFilter = new QPushButton(this);
    btnFilter->setFixedSize(44, 44);
    btnFilter->setIcon(QIcon(":/icons/Filter.svg"));
    btnFilter->setIconSize(QSize(24, 24));
    topPanel->addWidget(btnFilter);

    btnStart = new QPushButton(this);
    btnStart->setObjectName("btnStart");
    btnStart->setFixedHeight(44);
    btnStart->setMinimumWidth(120);
    setupButtonContent(btnStart, "НАЧАТЬ", ":/icons/Start.svg");
    topPanel->addWidget(btnStart);

    btnStop = new QPushButton(this);
    btnStop->setObjectName("btnStop");
    btnStop->setFixedHeight(44);
    btnStop->setMinimumWidth(120);
    setupButtonContent(btnStop, "СТОП", ":/icons/Stop.svg");
    btnStop->hide();
    topPanel->addWidget(btnStop);

    filterWidget = new FilterWidget(this);
    // FilterWidget floats over the main window, so we don't add it to mainLayout
    filterWidget->hide();
    connect(filterWidget, &FilterWidget::filtersApplied, this, &UI::applySimpleFilter);

    captureLayout->addLayout(topPanel);

    // Table
    packetTable = new QTableWidget(0, 5, this);
    packetTable->setHorizontalHeaderLabels({"ВРЕМЯ", "ПРОТОКОЛ", "ОТПРАВИТЕЛЬ", "ПОЛУЧАТЕЛЬ", "ИНФОРМАЦИЯ"});
    packetTable->horizontalHeader()->setStretchLastSection(true);
    packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    packetTable->setAlternatingRowColors(false);
    packetTable->setShowGrid(true);
    packetTable->verticalHeader()->setVisible(false);
    packetTable->setFocusPolicy(Qt::NoFocus);
    captureLayout->addWidget(packetTable);

    // Bottom Panel
    auto *bottomPanel = new QHBoxLayout();
    lblStatistics = new QLabel("Захвачено: 0 | Отображается: 0 | Общий объем: 0 байт", this);
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
    captureLayout->addLayout(bottomPanel);

    // Connections
    connect(btnNavCapture, &QPushButton::clicked, this, &UI::showCaptureView);
    connect(btnNavAnalysis, &QPushButton::clicked, this, &UI::showAnalysisView);
    connect(packetTable, &QTableWidget::cellDoubleClicked, this, &UI::showPacketDetails);

    connect(btnStart, &QPushButton::clicked, this, &UI::onStartClicked);
    connect(btnStop, &QPushButton::clicked, this, &UI::onStopClicked);
    connect(btnClearTable, &QPushButton::clicked, this, [this]() {
        packetTable->setRowCount(0);
        allPackets.clear();
        displayedPackets.clear();
        Statistics::getInstance()->reset();
        AnomalyDetector::getInstance()->reset();
        updateStatistics();
    });
    connect(btnFilter, &QPushButton::clicked, this, [this, btnFilter]() {
        if (!filterWidget->isVisible()) {
            filterWidget->adjustSize();
            QPoint pos = btnFilter->mapTo(this, QPoint(btnFilter->width(), btnFilter->height()));
            pos.setX(pos.x() - filterWidget->width());
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
            displayedPackets.clear();
            Statistics::getInstance()->reset();
            AnomalyDetector::getInstance()->reset();

            for (auto p : packets) {
                allPackets.push_back(p);
                Statistics::getInstance()->update(p);
                AnomalyDetector::getInstance()->update(p);
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
        displayedPackets.clear();
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
    std::lock_guard<std::mutex> lock(queueMutex);
    pendingPackets.push_back(packet);
}

void UI::onPacketsReceivedBatch(const std::vector<std::shared_ptr<Packet>>& packets) {
    std::lock_guard<std::mutex> lock(queueMutex);
    pendingPackets.insert(pendingPackets.end(), packets.begin(), packets.end());
}

void UI::processPendingPackets() {
    std::vector<std::shared_ptr<Packet>> batch;
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        if (pendingPackets.empty()) return;
        batch = std::move(pendingPackets);
        pendingPackets.clear();
    }

    bool addedAny = false;
    packetTable->setUpdatesEnabled(false);
    for (const auto& packet : batch) {
        allPackets.push_back(packet);
        if (isPacketMatching(packet)) {
            addPacketToTable(packet);
            addedAny = true;
        }
    }
    packetTable->setUpdatesEnabled(true);

    if (addedAny) {
        packetTable->scrollToBottom();
        updateStatistics();
    }
}

void UI::addPacketToTable(std::shared_ptr<Packet> packet) {
    displayedPackets.push_back(packet);
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
}

void UI::setupButtonContent(QPushButton* btn, const QString& text, const QString& iconPath) {
    btn->setText("");
    btn->setIcon(QIcon());

    if (btn->layout()) {
        QLayoutItem* item;
        while ((item = btn->layout()->takeAt(0)) != nullptr) {
            delete item->widget();
            delete item;
        }
        delete btn->layout();
    }

    auto *layout = new QHBoxLayout(btn);
    layout->setContentsMargins(16, 0, 12, 0);

    auto *lblText = new QLabel(text, btn);
    lblText->setStyleSheet("color: white; font-weight: bold; border: none; background: transparent; font-size: 12px; letter-spacing: 1px;");
    lblText->setAttribute(Qt::WA_TransparentForMouseEvents);

    auto *lblIcon = new QLabel(btn);
    lblIcon->setPixmap(QIcon(iconPath).pixmap(24, 24));
    lblIcon->setStyleSheet("border: none; background: transparent;");
    lblIcon->setAttribute(Qt::WA_TransparentForMouseEvents);

    layout->addWidget(lblText);
    layout->addStretch();
    layout->addWidget(lblIcon);
}

void UI::applyStyles() {
    this->setStyleSheet(R"(
        QMainWindow { background-color: #0F172A; }
        QComboBox { background-color: #1E293B; border: 1px solid #334155; border-radius: 8px; color: #F8FAFC; padding: 0 12px; font-size: 13px; }
        QComboBox:hover {background-color: #334155}
        QComboBox QAbstractItemView { outline: 0px; background-color: #1E293B; color: #F8FAFC; selection-background-color: #3B82F6; }
        QComboBox::drop-down { border: none; width: 44px; padding-right: 0px; }
        QComboBox::down-arrow { image: url(":/icons/Choose.svg"); width: 20px; height: 20px; }
        QLineEdit { background-color: #1E293B; border: 1px solid #334155; border-radius: 8px; color: #F8FAFC; padding: 0 12px; font-size: 13px; }
        QLineEdit:focus { background-color: #334155; }
        QPushButton { border-radius: 8px; font-weight: bold; font-size: 12px; letter-spacing: 1px; color: white; border: 1px solid #334155; background: #1E293B; }
        QPushButton:hover { background-color: #334155; }
        QPushButton#btnStart { background-color: #22C55E; border: none; }
        QPushButton#btnStart:hover { background-color: #16A34A}
        QPushButton#btnStop { background-color: #EF4444; border: none; }
        QPushButton#btnStop:hover { background-color: #DC2626}
        QPushButton#btnUpload { background-color: #3B82F6; border: none; }
        QPushButton#btnUpload:hover { background-color: #2563EB}
        QPushButton#btnDownload { background-color: #22C55E; border: none; }
        QPushButton#btnDownload:hover { background-color: #16A34A}
        QTableWidget { background-color: #1E293B; border: 1px solid #334155; border-radius: 12px; color: #F8FAFC; gridline-color: #475569; selection-background-color: #334155; outline: none; }
        QHeaderView::section { background-color: #1E293B; color: #94A3B8; padding: 12px; border: none; border-right: 1px solid #475569; border-bottom: 2px solid #334155; font-weight: bold; font-size: 11px; }
        QTableWidget::item { padding: 12px; border-bottom: 1px solid #334155; font-family: 'JetBrains Mono'; font-size: 12px; }
        QTableWidget::item:focus { outline: none; border: none; }
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
    packetTable->setUpdatesEnabled(false);
    packetTable->setRowCount(0);
    displayedPackets.clear();
    for (const auto& packet : allPackets) {
        if (isPacketMatching(packet)) {
            addPacketToTable(packet);
        }
    }
    packetTable->setUpdatesEnabled(true);
    if (packetTable->rowCount() > 0) {
        packetTable->scrollToBottom();
    }
    updateStatistics();
}

void UI::updateStatistics() {
    int total = Statistics::getInstance()->getTotalPackets();
    int displayed = packetTable->rowCount();
    long long volume = Statistics::getInstance()->getTotalVolume();
    lblStatistics->setText(QString("Захвачено: %1 | Отображается: %2 | Общий объем: %3 байт").arg(total).arg(displayed).arg(volume));
}

void UI::showCaptureView() {
    stackedWidget->setCurrentWidget(captureWidget);
    btnNavCapture->setStyleSheet("QPushButton { font-weight: bold; color: white; background: #3B82F6; }QPushButton:hover { background-color: #2563EB; }");
    btnNavAnalysis->setStyleSheet("QPushButton { font-weight: bold; color: #94A3B8; background: #1E293B; }QPushButton:hover { background-color: #334155; }");
}

void UI::showAnalysisView() {
    updateAnalysisDashboard();
    analysisStackedWidget->setCurrentWidget(analysisDashboard);
    stackedWidget->setCurrentWidget(analysisWidget);
    btnNavCapture->setStyleSheet("QPushButton { font-weight: bold; color: #94A3B8; background: #1E293B; }QPushButton:hover { background-color: #334155; }");
    btnNavAnalysis->setStyleSheet("QPushButton { font-weight: bold; color: white; background: #3B82F6; }QPushButton:hover { background-color: #2563EB; }");
}

QPushButton* UI::createAnalysisBlock(const QString& title, const QString& value, const QString& color, int category) {
    auto *btn = new QPushButton(this);
    btn->setCursor(Qt::PointingHandCursor);
    btn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    btn->setMinimumHeight(110);
    btn->setStyleSheet(QString("QPushButton { background-color: #1E293B; border: 1px solid #334155; border-radius: 8px; text-align: left; }"
                               "QPushButton:hover { background-color: #334155; border-color: %1; }").arg(color));

    auto *layout = new QVBoxLayout(btn);
    layout->setContentsMargins(24, 24, 24, 24);
    layout->setSpacing(8);

    auto *lblTitle = new QLabel(title, btn);
    lblTitle->setStyleSheet("color: #94A3B8; font-size: 14px; background: transparent; border: none;");
    lblTitle->setWordWrap(true);
    lblTitle->setAttribute(Qt::WA_TransparentForMouseEvents);

    auto *lblValue = new QLabel(value, btn);
    lblValue->setStyleSheet(QString("color: %1; font-size: 26px; font-weight: bold; background: transparent; border: none;").arg(color));
    lblValue->setAttribute(Qt::WA_TransparentForMouseEvents);

    layout->addWidget(lblTitle);
    layout->addWidget(lblValue);

    connect(btn, &QPushButton::clicked, this, [this, category]() {
        showAnalysisTableForCategory(category);
    });

    return btn;
}

void UI::updateAnalysisDashboard() {
    // Clear existing layout
    auto clearLayout = [](QLayout* layout, auto& ref) -> void {
        if (!layout) return;
        while (QLayoutItem *item = layout->takeAt(0)) {
            if (QWidget* w = item->widget()) {
                w->deleteLater();
            }
            if (QLayout* childLayout = item->layout()) {
                ref(childLayout, ref);
                childLayout->deleteLater();
            }
            delete item;
        }
    };
    clearLayout(analysisDashboardLayout, clearLayout);

    auto stats = Statistics::getInstance();

    // Общая статистика
    auto *lblGeneralStats = new QLabel("Общая статистика", analysisDashboard);
    lblGeneralStats->setStyleSheet("color: white; font-size: 20px; font-weight: bold; margin-bottom: 8px;");
    analysisDashboardLayout->addWidget(lblGeneralStats);

    auto *generalLayout = new QHBoxLayout();
    generalLayout->setSpacing(16);
    generalLayout->addWidget(createAnalysisBlock("Шифрованный трафик (TLS/SSL)", QString::number(stats->getEncryptedPackets()), "#10B981", static_cast<int>(AnalysisCategory::Encrypted)));
    generalLayout->addWidget(createAnalysisBlock("Нешифрованный трафик", QString::number(stats->getUnencryptedPackets()), "#F59E0B", static_cast<int>(AnalysisCategory::Unencrypted)));
    generalLayout->addWidget(createAnalysisBlock("DNS Запросы", QString::number(stats->getDnsQueries()), "#3B82F6", static_cast<int>(AnalysisCategory::DNS)));
    analysisDashboardLayout->addLayout(generalLayout);

    // Подозрительная активность
    auto *lblSuspicious = new QLabel("Подозрительная активность", analysisDashboard);
    lblSuspicious->setStyleSheet("color: white; font-size: 20px; font-weight: bold; margin-top: 24px; margin-bottom: 8px;");
    analysisDashboardLayout->addWidget(lblSuspicious);

    auto anomalyDetector = AnomalyDetector::getInstance();
    bool hasAnomalies = (anomalyDetector->getSynFloodCount() > 0 || anomalyDetector->getSuspiciousPortPackets() > 0 || !anomalyDetector->getDosAttackers().isEmpty());

    if (hasAnomalies) {
        auto *suspiciousLayout = new QHBoxLayout();
        suspiciousLayout->setSpacing(16);
        suspiciousLayout->addWidget(createAnalysisBlock("SYN Флуд (Возможный DoS)", QString::number(anomalyDetector->getSynFloodCount()), "#EF4444", static_cast<int>(AnalysisCategory::SYNFlood)));
        suspiciousLayout->addWidget(createAnalysisBlock("Подозрительные порты", QString::number(anomalyDetector->getSuspiciousPortPackets()), "#EF4444", static_cast<int>(AnalysisCategory::SuspiciousPorts)));
        suspiciousLayout->addWidget(createAnalysisBlock("Источники DoS атак", QString::number(anomalyDetector->getDosAttackers().size()), "#EF4444", static_cast<int>(AnalysisCategory::DoS)));
        analysisDashboardLayout->addLayout(suspiciousLayout);
    } else {
        auto *lblNoAnomalies = new QLabel("Подозрительная активность не обнаружена", analysisDashboard);
        lblNoAnomalies->setStyleSheet("background-color: #1E293B; border: 1px solid #334155; border-radius: 8px; color: #10B981; font-size: 16px; padding: 24px; text-align: center;");
        lblNoAnomalies->setAlignment(Qt::AlignCenter);
        analysisDashboardLayout->addWidget(lblNoAnomalies);
    }

    analysisDashboardLayout->addStretch();
}

void UI::addPacketToAnalysisTable(std::shared_ptr<Packet> packet) {
    analysisDisplayedPackets.push_back(packet);
    int row = analysisTable->rowCount();
    analysisTable->insertRow(row);

    analysisTable->setItem(row, 0, new QTableWidgetItem(QString::number(row + 1)));
    analysisTable->setItem(row, 1, new QTableWidgetItem(packet->getTime()));
    analysisTable->setItem(row, 2, new QTableWidgetItem(QString("%1:%2").arg(packet->getSource()).arg(packet->getSrcPort())));
    analysisTable->setItem(row, 3, new QTableWidgetItem(QString("%1:%2").arg(packet->getDestination()).arg(packet->getDestPort())));
    analysisTable->setItem(row, 4, new QTableWidgetItem(packet->getProtocol()));
}

void UI::showAnalysisTableForCategory(int categoryInt) {
    currentAnalysisCategory = static_cast<AnalysisCategory>(categoryInt);
    analysisTable->setRowCount(0);
    analysisDisplayedPackets.clear();

    auto stats = Statistics::getInstance();
    auto anomalyDetector = AnomalyDetector::getInstance();

    for (const auto& p : allPackets) {
        bool match = false;
        switch (currentAnalysisCategory) {
        case AnalysisCategory::Encrypted:       match = stats->isEncrypted(p); break;
        case AnalysisCategory::Unencrypted:     match = stats->isUnencrypted(p); break;
        case AnalysisCategory::DNS:             match = stats->isDNS(p); break;
        case AnalysisCategory::SYNFlood:        match = anomalyDetector->isSYNFlood(p); break;
        case AnalysisCategory::SuspiciousPorts: match = anomalyDetector->isSuspiciousPort(p); break;
        case AnalysisCategory::DoS:             match = anomalyDetector->getDosAttackers().contains(p->getSource()); break;
        }
        if (match) {
            addPacketToAnalysisTable(p);
        }
    }

    analysisStackedWidget->setCurrentWidget(analysisTableContainer);
}

void UI::showAnalysisDashboard() {
    analysisStackedWidget->setCurrentWidget(analysisDashboard);
}

void UI::onAnalysisTableDoubleClicked(int row, int column) {
    Q_UNUSED(column);
    if (row < 0 || row >= static_cast<int>(analysisDisplayedPackets.size())) return;

    prevWidgetForDetails = analysisWidget;

    auto packet = analysisDisplayedPackets[row];
    showPacketDetailsWithPacket(packet, row);
}

void UI::showPacketDetails(int row, int column) {
    Q_UNUSED(column);
    if (row < 0 || row >= static_cast<int>(displayedPackets.size())) return;

    prevWidgetForDetails = captureWidget;
    auto packet = displayedPackets[row];
    showPacketDetailsWithPacket(packet, row);
}

void UI::backFromPacketDetails() {
    stackedWidget->setCurrentWidget(prevWidgetForDetails);
}

void UI::showPacketDetailsWithPacket(std::shared_ptr<Packet> packet, int displayRow) {
    QString summary = QString("Пакет: %1 | Протокол: %2\nОт: %3:%4\nК: %5:%6\nИнформация: %7")
                          .arg(displayRow + 1)
                          .arg(packet->getProtocol())
                          .arg(packet->getSource())
                          .arg(packet->getSrcPort())
                          .arg(packet->getDestination())
                          .arg(packet->getDestPort())
                          .arg(packet->getInfo());

    lblDetailSummary->setText(summary);

    QString rawStr;
    const std::vector<uint8_t>& rawData = packet->getRawData();

    auto bytesToHex = [](const std::vector<uint8_t>& data, size_t start, size_t len) {
        QString hex;
        for (size_t i = 0; i < len && start + i < data.size(); ++i) {
            hex += QString("%1 ").arg(data[start + i], 2, 16, QChar('0')).toUpper();
        }
        return hex.trimmed();
    };

    QString html;

    auto makeRow = [](const QString& hex, const QString& name, const QString& desc) {
        return QString("<tr>"
                       "<td style='padding: 8px; background-color: #334155; color: #38BDF8; font-family: monospace; text-align: center; border-radius: 4px; margin-bottom: 4px;'>%1</td>"
                       "<td style='padding: 8px;' width='20'>&rarr;</td>"
                       "<td style='padding: 8px; background-color: #334155; color: #F8FAFC; border-radius: 4px; margin-bottom: 4px;'><b>%2</b></td>"
                       "<td style='padding: 8px;' width='20'>&rarr;</td>"
                       "<td style='padding: 8px; background-color: #334155; color: #CBD5E1; border-radius: 4px; margin-bottom: 4px; width: 100%;'>%3</td>"
                       "</tr>").arg(hex, name, desc);
    };

    auto makeHeader = [](const QString& title) {
        return QString("<h3 style='color: #F8FAFC; text-align: left; margin-top: 16px; margin-bottom: 8px;'>%1</h3>"
                       "<table style='width: 100%; border-spacing: 0 4px;'>").arg(title);
    };

    auto endTable = []() {
        return QString("</table>");
    };

    if (rawData.size() >= 14) {
        html += makeHeader("Ethernet Заголовок");

        QString macDestStr, macSrcStr;
        for(int i=0; i<6; i++) {
            macDestStr += QString("%1").arg(rawData[i], 2, 16, QChar('0')).toUpper() + (i<5?":":"");
            macSrcStr += QString("%1").arg(rawData[6+i], 2, 16, QChar('0')).toUpper() + (i<5?":":"");
        }
        html += makeRow(bytesToHex(rawData, 0, 6), "MAC Назначения", "Уникальный физический адрес получателя " + macDestStr);
        html += makeRow(bytesToHex(rawData, 6, 6), "MAC Источника", "Уникальный физический адрес отправителя " + macSrcStr);

        uint16_t etherType = (rawData[12] << 8) | rawData[13];
        QString ethTypeDesc = "Тип вложенного протокола";
        if (etherType == 0x0800) ethTypeDesc += " (IPv4)";
        else if (etherType == 0x86DD) ethTypeDesc += " (IPv6)";
        else if (etherType == 0x0806) ethTypeDesc += " (ARP)";
        html += makeRow(bytesToHex(rawData, 12, 2), "EtherType", ethTypeDesc);
        html += endTable();

        if (rawData.size() >= 34 && etherType == 0x0800) {
            html += makeHeader("IPv4 Заголовок");
            html += makeRow(bytesToHex(rawData, 14, 1), "Версия и IHL", "Версия IP и длина заголовка");
            html += makeRow(bytesToHex(rawData, 15, 1), "TOS", "Тип обслуживания (качество и приоритет)");

            uint16_t totalLen = (rawData[16] << 8) | rawData[17];
            html += makeRow(bytesToHex(rawData, 16, 2), "Общая длина", QString("Длина пакета: %1 байт").arg(totalLen));
            html += makeRow(bytesToHex(rawData, 18, 2), "Идентификация", "Уникальный ID для сборки фрагментов");
            html += makeRow(bytesToHex(rawData, 20, 2), "Флаги / Смещение", "Управление фрагментацией");

            uint8_t ttl = rawData[22];
            html += makeRow(bytesToHex(rawData, 22, 1), "TTL", QString("Время жизни: максимум %1 переходов (хопов)").arg(ttl));
            html += makeRow(bytesToHex(rawData, 23, 1), "Протокол", QString("Протокол следующего уровня (%1)").arg(packet->getProtocol()));
            html += makeRow(bytesToHex(rawData, 24, 2), "Контрольная сумма", "Проверка целостности заголовка IP");
            html += makeRow(bytesToHex(rawData, 26, 4), "IP Источника", QString("IP-адрес отправителя: %1").arg(packet->getSource()));
            html += makeRow(bytesToHex(rawData, 30, 4), "IP Назначения", QString("IP-адрес получателя: %1").arg(packet->getDestination()));
            html += endTable();

            int ipHeaderLen = (rawData[14] & 0x0F) * 4;
            size_t payloadOffset = 14 + ipHeaderLen;

            if (rawData.size() >= payloadOffset + 8) {
                if (packet->getProtocol() == "TCP") {
                    html += makeHeader("TCP Заголовок");
                    html += makeRow(bytesToHex(rawData, payloadOffset, 2), "Порт Источника", QString("Порт: %1").arg(packet->getSrcPort()));
                    html += makeRow(bytesToHex(rawData, payloadOffset + 2, 2), "Порт Назначения", QString("Порт: %1").arg(packet->getDestPort()));
                    if (rawData.size() >= payloadOffset + 20) {
                        html += makeRow(bytesToHex(rawData, payloadOffset + 4, 4), "Sequence Number", "Номер последовательности для сборки потока");
                        html += makeRow(bytesToHex(rawData, payloadOffset + 8, 4), "Acknowledgment", "Номер подтверждения для надежности");
                        html += makeRow(bytesToHex(rawData, payloadOffset + 12, 1), "Data Offset", "Длина TCP заголовка");

                        uint8_t flags = rawData[payloadOffset + 13];
                        QString flagsStr;
                        if (flags & 0x02) flagsStr += "SYN ";
                        if (flags & 0x10) flagsStr += "ACK ";
                        if (flags & 0x01) flagsStr += "FIN ";
                        if (flags & 0x04) flagsStr += "RST ";
                        if (flags & 0x08) flagsStr += "PSH ";
                        if (flagsStr.isEmpty()) flagsStr = "Специфичные флаги";
                        else flagsStr = "Установлены флаги: " + flagsStr.trimmed();

                        html += makeRow(bytesToHex(rawData, payloadOffset + 13, 1), "Флаги", flagsStr);

                        uint16_t winArea = (rawData[payloadOffset + 14] << 8) | rawData[payloadOffset + 15];
                        html += makeRow(bytesToHex(rawData, payloadOffset + 14, 2), "Размер окна", QString("Буфер приема: %1 байт").arg(winArea));
                        html += makeRow(bytesToHex(rawData, payloadOffset + 16, 2), "Контрольная сумма", "Проверка на наличие ошибок в TCP-сегменте");
                        html += makeRow(bytesToHex(rawData, payloadOffset + 18, 2), "Urgent Pointer", "Указатель важных (срочных) данных");
                        html += endTable();

                        int tcpHeaderLen = ((rawData[payloadOffset + 12] >> 4) & 0x0F) * 4;
                        size_t dataOffset = payloadOffset + tcpHeaderLen;

                        if (dataOffset < rawData.size()) {
                            html += makeHeader("Payload");
                            if (packet->getSrcPort() == 443 || packet->getDestPort() == 443) {
                                html += makeRow(bytesToHex(rawData, dataOffset, rawData.size() - dataOffset), "Зашифрованный Payload", "Необходим ключ для расшифровки TLS/SSL");
                            } else {
                                html += makeRow(bytesToHex(rawData, dataOffset, rawData.size() - dataOffset), "Данные (Data)", "Полезная нагрузка пакета уровня приложения");
                            }
                            html += endTable();
                        }
                    } else {
                        html += endTable();
                    }
                } else if (packet->getProtocol() == "UDP") {
                    html += makeHeader("UDP Заголовок");
                    html += makeRow(bytesToHex(rawData, payloadOffset, 2), "Порт Источника", QString("Порт: %1").arg(packet->getSrcPort()));
                    html += makeRow(bytesToHex(rawData, payloadOffset + 2, 2), "Порт Назначения", QString("Порт: %1").arg(packet->getDestPort()));

                    uint16_t udpLen = (rawData[payloadOffset + 4] << 8) | rawData[payloadOffset + 5];
                    html += makeRow(bytesToHex(rawData, payloadOffset + 4, 2), "Длина", QString("Заголовок и данные: %1 байт").arg(udpLen));
                    html += makeRow(bytesToHex(rawData, payloadOffset + 6, 2), "Контрольная сумма", "Проверка на наличие ошибок");
                    html += endTable();

                    size_t dataOffset = payloadOffset + 8;
                    if (dataOffset < rawData.size()) {
                        html += makeHeader("Payload");
                        if (packet->getSrcPort() == 443 || packet->getDestPort() == 443) {
                            html += makeRow(bytesToHex(rawData, dataOffset, rawData.size() - dataOffset), "Зашифрованный Payload", "Необходим ключ для расшифровки TLS/SSL/QUIC");
                        } else {
                            html += makeRow(bytesToHex(rawData, dataOffset, rawData.size() - dataOffset), "Данные (Data)", "Полезная нагрузка пакета UDP");
                        }
                        html += endTable();
                    }
                } else if (packet->getProtocol() == "ICMP") {
                    html += makeHeader("ICMP Заголовок");
                    html += makeRow(bytesToHex(rawData, payloadOffset, 1), "Тип", "Тип управляющего сообщения");
                    html += makeRow(bytesToHex(rawData, payloadOffset + 1, 1), "Код", "Дополнительный код (например, причина недостижимости)");
                    html += makeRow(bytesToHex(rawData, payloadOffset + 2, 2), "Контрольная сумма", "Проверка заголовка и данных ICMP");
                    html += endTable();

                    if (rawData.size() > payloadOffset + 4) {
                        html += makeHeader("Payload");
                        html += makeRow(bytesToHex(rawData, payloadOffset + 4, rawData.size() - payloadOffset - 4), "Данные (Data)", "Дополнительная информация ICMP");
                        html += endTable();
                    }
                } else {
                    html += makeHeader("Payload");
                    html += makeRow(bytesToHex(rawData, payloadOffset, rawData.size() - payloadOffset), "Неизвестный Payload", "Данные неподдерживаемого протокола");
                    html += endTable();
                }
            }
        } else if (rawData.size() >= 34 && etherType == 0x86DD) {
            html += makeHeader("IPv6 Заголовок");
            html += makeRow(bytesToHex(rawData, 14, 40), "IPv6 Заголовок", "базовый заголовок IPv6");
            html += endTable();
            if (rawData.size() > 54) {
                html += makeHeader("Payload");
                html += makeRow(bytesToHex(rawData, 54, rawData.size() - 54), "Данные", "Данные IPv6");
                html += endTable();
            }
        }
    } else {
        html += makeHeader("Ошибка");
        html += makeRow(bytesToHex(rawData, 0, rawData.size()), "Некорректный пакет", "Слишком короткий пакет для анализа (менее 14 байт)");
        html += endTable();
    }

    textRawData->setHtml(html);

    stackedWidget->setCurrentWidget(packetDetailsWidget);
}
