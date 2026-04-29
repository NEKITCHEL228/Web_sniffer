#include "ui.h"
#include "sniffer.h"
#include "snifferfacade.h"
#include "filterdialog.h"
#include "packet.h"
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

    btnRefreshInterfaces = new QPushButton(this);
    btnRefreshInterfaces->setFixedSize(44, 44);
    btnRefreshInterfaces->setToolTip("Обновить список интерфейсов");
    btnRefreshInterfaces->setIcon(QIcon(":/icons/Settings.svg")); // Using settings icon for refresh
    topPanel->addWidget(btnRefreshInterfaces);

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

    mainLayout->addLayout(topPanel);

    // Table
    packetTable = new QTableWidget(0, 6, this);
    packetTable->setHorizontalHeaderLabels({"НАЧАЛО", "КОНЕЦ", "ПРОТОКОЛ", "ОТПРАВИТЕЛЬ", "ПОЛУЧАТЕЛЬ", "ИНФОРМАЦИЯ"});
    packetTable->horizontalHeader()->setStretchLastSection(true);
    packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    packetTable->setAlternatingRowColors(false);
    packetTable->setShowGrid(false);
    packetTable->verticalHeader()->setVisible(false);
    mainLayout->addWidget(packetTable);

    // Bottom Panel
    auto *bottomPanel = new QHBoxLayout();
    auto *btnUpload = new QPushButton("ЗАГРУЗИТЬ ⬆", this);
    auto *btnDownload = new QPushButton("СКАЧАТЬ ⬇", this);
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
    connect(btnRefreshInterfaces, &QPushButton::clicked, this, &UI::onRefreshInterfaces);
    connect(btnFilter, &QPushButton::clicked, this, [this]() {
        FilterDialog dialog(this);
        dialog.exec();
    });

    resize(1024, 768);
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
    btnStart->hide();
    btnStop->show();
    facade->startCapture(iface);
}

void UI::onStopClicked() {
    btnStart->show();
    btnStop->hide();
    facade->stopCapture();
}

void UI::onPacketReceived(std::shared_ptr<Packet> packet) {
    addPacketToTable(packet);
}

void UI::addPacketToTable(std::shared_ptr<Packet> packet) {
    int row = packetTable->rowCount();
    packetTable->insertRow(row);
    packetTable->setItem(row, 0, new QTableWidgetItem(packet->getTime()));
    packetTable->setItem(row, 1, new QTableWidgetItem("-"));
    packetTable->setItem(row, 2, new QTableWidgetItem(packet->getProtocol()));
    packetTable->setItem(row, 3, new QTableWidgetItem(packet->getSource()));
    packetTable->setItem(row, 4, new QTableWidgetItem(packet->getDestination()));
    packetTable->setItem(row, 5, new QTableWidgetItem(packet->getInfo()));
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
