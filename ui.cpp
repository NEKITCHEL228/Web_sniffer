#include "ui.h"
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QTableView>
#include <QLabel>
#include <QHeaderView>

UI::UI(QWidget *parent)
    : QMainWindow(parent)
{
    setupUI();

    resize(800, 600);
    setWindowTitle("C++ Web Sniffer");
}

UI::~UI()
{

}

void UI::setupUI()
{
    // 1. Создаем центральный виджет (основа окна)
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    // 2. Создаем компоновщики
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget); // Главный вертикальный
    QHBoxLayout *topPanel = new QHBoxLayout();                // Панель управления (горизонтальная)

    // 3. Создаем сами элементы (передаем this, чтобы они стали детьми текущего окна)
    btnStart = new QPushButton("Start Capture", this);
    btnStop = new QPushButton("Stop", this);
    btnStop->setEnabled(false); // Выключаем кнопку стоп при запуске

    filterInput = new QLineEdit(this);
    filterInput->setPlaceholderText("Enter filter (e.g. port 80)");

    packetTable = new QTableView(this);
    // Настройки таблицы (чтобы она тянулась на всё окно)
    packetTable->horizontalHeader()->setStretchLastSection(true);

    // 4. Собираем верхнюю панель (слева направо)
    topPanel->addWidget(btnStart);
    topPanel->addWidget(btnStop);
    topPanel->addWidget(new QLabel("Filter:", this));
    topPanel->addWidget(filterInput);

    // 5. Собираем всё в главное окно (сверху вниз)
    mainLayout->addLayout(topPanel);
    mainLayout->addWidget(packetTable);

    // 6. Подключаем сигналы кнопок к нашим слотам
    connect(btnStart, &QPushButton::clicked, this, &UI::onStartClicked);
    connect(btnStop, &QPushButton::clicked, this, &UI::onStopClicked);
}

void UI::onStartClicked()
{
    btnStart->setEnabled(false);
    btnStop->setEnabled(true);

    // Тут будет вызов: facade->start();
}

void UI::onStopClicked()
{
    btnStart->setEnabled(true);
    btnStop->setEnabled(false);

    // Тут будет вызов: facade->stop();
}
