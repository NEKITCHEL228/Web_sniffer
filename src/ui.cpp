#include "../include/ui.h"
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QTableWidget>
#include <QHeaderView>
#include <QIcon>
#include <QApplication>

UI::UI(QWidget *parent) : QMainWindow(parent)
{
    setupUI();
    applyStyles();

    resize(1200, 800);
    setWindowTitle("Web Sniffer");
}

UI::~UI() {}

void UI::setupUI()
{
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(20, 20, 20, 20); // Отступы от краев окна
    mainLayout->setSpacing(20); // Расстояние между верхней панелью и таблицей

    // === ВЕРХНЯЯ ПАНЕЛЬ ===
    QHBoxLayout *topPanel = new QHBoxLayout();
    topPanel->setSpacing(15);

    // Выбор интерфейса (ComboBox)
    comboInterface = new QComboBox(this);
    comboInterface->addItem("Выберите сетевой интерфейс");
    comboInterface->addItem("Ethernet0");
    comboInterface->addItem("Wi-Fi");
    comboInterface->setMinimumHeight(40);
    comboInterface->setMinimumWidth(250);

    // Поле фильтра
    filterInput = new QLineEdit(this);
    filterInput->setPlaceholderText("Фильтр (например, tcp port 80)");
    filterInput->setMinimumHeight(40);

    // Кнопка Старт
    btnStart = new QPushButton("Начать", this);
    btnStart->setMinimumHeight(40);
    btnStart->setMinimumWidth(120);
    btnStart->setIcon(QIcon(":/icons/Start.svg"));
    btnStart->setLayoutDirection(Qt::RightToLeft); // Иконка справа от текста

    // Кнопка Стоп (изначально скрыта или выключена)
    btnStop = new QPushButton("Стоп", this);
    btnStop->setMinimumHeight(40);
    btnStop->setMinimumWidth(120);
    btnStop->setIcon(QIcon(":/icons/Stop.svg"));
    btnStop->setLayoutDirection(Qt::RightToLeft);
    btnStop->hide(); // Скрываем по умолчанию, как на макете

    topPanel->addWidget(comboInterface);
    topPanel->addWidget(filterInput, 1); // 1 = растягиваться на всё свободное место
    topPanel->addWidget(btnStart);
    topPanel->addWidget(btnStop);

    // === ТАБЛИЦА ===
    packetTable = new QTableWidget(0, 6, this);
    packetTable->setHorizontalHeaderLabels({
        "Начало", "Конец", "Транспортный протокол",
        "IP-адрес отправителя", "IP-адрес получателя", "Информация"
    });

    // Настройки поведения таблицы
    packetTable->horizontalHeader()->setStretchLastSection(true);
    packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable->setShowGrid(false); // Скрываем стандартную сетку (сделаем кастомную через QSS)
    packetTable->verticalHeader()->setVisible(false); // Скрываем нумерацию строк слева

    // === СБОРКА И ПОДКЛЮЧЕНИЕ СИГНАЛОВ ===
    mainLayout->addLayout(topPanel);
    mainLayout->addWidget(packetTable);

    connect(btnStart, &QPushButton::clicked, this, &UI::onStartClicked);
    connect(btnStop, &QPushButton::clicked, this, &UI::onStopClicked);
    connect(comboInterface, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &UI::onInterfaceChanged);
}

void UI::applyStyles()
{
    // Ваша цветовая палитра в формате QSS
    QString qss = R"(
        /* ОСНОВНОЙ ФОН */
        QWidget {
            background-color: #0F172A;
            color: #E2E8F0;
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 14px;
        }

        /* ПОЛЕ ВВОДА (ФИЛЬТР) И COMBOBOX (ПО УМОЛЧАНИЮ) */
        QLineEdit, QComboBox {
            background-color: #1E293B;
            border: 1px solid #475569;
            border-radius: 6px;
            padding: 0 15px;
            color: #E2E8F0;
        }
        QLineEdit:focus, QComboBox:focus, QComboBox:hover {
            border: 1px solid #3B82F6; /* Синий акцент при наведении */
            background-color: #334155;
        }

        /* НАСТРОЙКА СТРЕЛОЧКИ COMBOBOX */
        QComboBox::drop-down {
            border: none;
            padding-right: 15px;
        }
        QComboBox::down-arrow {
            image: url(:/icons/Choose.svg);
            width: 14px;
            height: 14px;
        }
        QComboBox QAbstractItemView {
            background-color: #1E293B;
            border: 1px solid #475569;
            selection-background-color: #334155;
        }

        /* КНОПКА СТАРТ (ЗЕЛЕНАЯ) */
        QPushButton#btnStart {
            background-color: #22C55E;
            color: white;
            border: none;
            border-radius: 6px;
            font-weight: bold;
            padding: 0 15px;
        }
        QPushButton#btnStart:hover {
            background-color: #16A34A;
        }

        /* КНОПКА СТОП (КРАСНАЯ) */
        QPushButton#btnStop {
            background-color: #EF4444;
            color: white;
            border: none;
            border-radius: 6px;
            font-weight: bold;
            padding: 0 15px;
        }
        QPushButton#btnStop:hover {
            background-color: #DC2626;
        }

        /* ТАБЛИЦА ПАКЕТОВ */
        QTableWidget {
            background-color: #0F172A;
            border: 1px solid #475569;
            border-radius: 6px;
        }
        QTableWidget::item {
            border-bottom: 1px solid #1E293B; /* Кастомная сетка */
            padding-left: 10px;
        }
        QTableWidget::item:selected {
            background-color: #052E1A; /* Мягкий зеленый при выделении */
            color: #E2E8F0;
        }

        /* ЗАГОЛОВКИ ТАБЛИЦЫ */
        QHeaderView::section {
            background-color: #1E293B;
            color: #94A3B8;
            border: none;
            border-right: 1px solid #475569;
            border-bottom: 1px solid #475569;
            padding: 8px 10px;
            font-weight: bold;
            text-align: left;
        }
        QHeaderView::section:last {
            border-right: none;
        }
    )";

    this->setStyleSheet(qss);

    // Присваиваем объектам ObjectName, чтобы QSS понимал, где какая кнопка
    btnStart->setObjectName("btnStart");
    btnStop->setObjectName("btnStop");
}

void UI::setInterfaceError(bool hasError)
{
    if (hasError) {
        // Применяем Желтый стиль (предупреждение)
        comboInterface->setStyleSheet(R"(
            QComboBox {
                background-color: #EAB308;
                border: 1px solid #CA8A04;
                border-radius: 6px;
                padding: 0 15px;
                color: #422006;
                font-weight: bold;
            }
            QComboBox:hover {
                background-color: #CA8A04;
            }
        )");
    } else {
        // Сбрасываем стиль (вернется к глобальному QSS)
        comboInterface->setStyleSheet("");
    }
}

void UI::onStartClicked()
{
    // Проверка: выбран ли интерфейс (индекс 0 - это плейсхолдер)
    if (comboInterface->currentIndex() == 0) {
        setInterfaceError(true);
        return;
    }

    // Меняем кнопки
    btnStart->hide();
    btnStop->show();

    // Блокируем настройки во время захвата
    comboInterface->setEnabled(false);
    filterInput->setEnabled(false);

    // Запуск (вызов фасада)
    // facade->start();
}

void UI::onStopClicked()
{
    btnStop->hide();
    btnStart->show();

    comboInterface->setEnabled(true);
    filterInput->setEnabled(true);

    // Остановка (вызов фасада)
    // facade->stop();
}

void UI::onInterfaceChanged()
{
    // Если пользователь выбрал интерфейс после ошибки - убираем желтый цвет
    if (comboInterface->currentIndex() != 0) {
        setInterfaceError(false);
    }
}
