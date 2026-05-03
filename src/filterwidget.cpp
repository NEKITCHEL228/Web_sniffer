#include "filterwidget.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>

FilterWidget::FilterWidget(QWidget *parent) : QWidget(parent) {
    setAttribute(Qt::WA_StyledBackground, true);
    setObjectName("filterWidgetObj");
    setupUI();
    applyStyles();
    hide(); // Ensure it's hidden initially
}

void FilterWidget::setupUI() {
    auto *mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(24, 24, 24, 24);
    mainLayout->setSpacing(20);

    // Title and Close Button
    auto *headerLayout = new QHBoxLayout();
    auto *title = new QLabel("Простой фильтр", this);
    title->setStyleSheet("font-size: 24px; font-weight: bold; color: white;");
    headerLayout->addWidget(title);
    headerLayout->addStretch();

    auto *btnClose = new QPushButton(this);
    btnClose->setFixedSize(44, 44);
    btnClose->setObjectName("btnClose");
    btnClose->setIcon(QIcon(":/icons/CloseButton.svg"));
    btnClose->setIconSize(QSize(28, 28));
    headerLayout->addWidget(btnClose);
    mainLayout->addLayout(headerLayout);

    mainLayout->addSpacing(10);

    auto *gridLayout = new QGridLayout();
    gridLayout->setVerticalSpacing(8);
    gridLayout->setHorizontalSpacing(16);

    auto addEntry = [&](int row, const QString &name, QLineEdit *&editOut, QPushButton *&btnOut) {
        auto *lbl = new QLabel(name, this);
        lbl->setStyleSheet("color: #F8FAFC; font-size: 14px; font-weight: bold;");
        gridLayout->addWidget(lbl, row * 2, 0, 1, 3);

        editOut = new QLineEdit(this);
        editOut->setFixedHeight(44);
        editOut->setMinimumWidth(320);
        gridLayout->addWidget(editOut, row * 2 + 1, 0, 1, 1);

        btnOut = new QPushButton(this);
        btnOut->setFixedSize(44, 44);
        btnOut->setObjectName("btnRowSave");
        btnOut->setIcon(QIcon(":/icons/Filter.svg"));
        btnOut->setIconSize(QSize(24, 24));
        btnOut->setCheckable(true);
        gridLayout->addWidget(btnOut, row * 2 + 1, 1, 1, 1);

        connect(editOut, &QLineEdit::textChanged, this, [btnOut](const QString &text) {
            btnOut->setChecked(!text.isEmpty());
        });
    };

    gridLayout->setColumnStretch(0, 1);
    gridLayout->setColumnStretch(1, 0);
    gridLayout->setColumnStretch(2, 1); // spacer between filter and save
    gridLayout->setColumnStretch(3, 0);

    addEntry(0, "Фильтр по порту", portEdit, portBtn);
    addEntry(1, "Фильтр по IP-адресу получателя", ipEdit, ipBtn);
    addEntry(2, "Фильтр по IP-адресу отправителя", srcIpEdit, srcIpBtn);
    addEntry(3, "Фильтр по протоколу", protoEdit, protoBtn);

    btnSave = new QPushButton(this);
    btnSave->setObjectName("btnSave");
    btnSave->setFixedHeight(44);
    btnSave->setMinimumWidth(160);

    auto *saveLayout = new QHBoxLayout(btnSave);
    saveLayout->setContentsMargins(16, 0, 12, 0);
    auto *lblSaveText = new QLabel("Сохранить", btnSave);
    lblSaveText->setStyleSheet("color: white; font-weight: bold; font-size: 14px; border: none; background: transparent;");
    lblSaveText->setAttribute(Qt::WA_TransparentForMouseEvents);
    auto *lblSaveIcon = new QLabel(btnSave);
    lblSaveIcon->setPixmap(QIcon(":/icons/SaveFile.svg").pixmap(24, 24));
    lblSaveIcon->setStyleSheet("border: none; background: transparent;");
    lblSaveIcon->setAttribute(Qt::WA_TransparentForMouseEvents);
    saveLayout->addWidget(lblSaveText);
    saveLayout->addStretch();
    saveLayout->addWidget(lblSaveIcon);

    gridLayout->addWidget(btnSave, 7, 3, 1, 1, Qt::AlignRight);

    mainLayout->addLayout(gridLayout);

    connect(btnClose, &QPushButton::clicked, this, &FilterWidget::hide);
    connect(btnSave, &QPushButton::clicked, this, [this]() {
        emit filtersApplied(getFilterData());
        hide();
    });
}

SimpleFilterData FilterWidget::getFilterData() const {
    return {
        portBtn->isChecked(), portEdit->text(),
        ipBtn->isChecked(), ipEdit->text(),
        srcIpBtn->isChecked(), srcIpEdit->text(),
        protoBtn->isChecked(), protoEdit->text()
    };
}

void FilterWidget::applyStyles() {
    this->setStyleSheet(R"(
        QWidget#filterWidgetObj {
            background-color: #0F172A;
            border-radius: 12px;
            border: 1px solid #475569;
        }
        QLabel {
            color: #F8FAFC;
            font-family: 'Inter', sans-serif;
        }
        QLineEdit {
            background-color: #1E293B;
            border: 1px solid #334155;
            border-radius: 8px;
            color: white;
            padding-left: 12px;
            font-size: 14px;
        }
        QLineEdit:focus {
            background-color: #334155;
            border: 1px solid #3B82F6;
        }
        QPushButton#btnClose {
            background-color: #EF4444;
            border-radius: 8px;
            border: none;
        }
        QPushButton#btnClose:hover { background-color: #DC2626; }

        QPushButton#btnRowSave {
            background-color: #EF4444;
            border-radius: 8px;
            border: none;
            color: white;
        }
        QPushButton#btnRowSave:hover {
            background-color: #DC2626;
        }
        QPushButton#btnRowSave:checked {
            background-color: #22C55E;
            border: none;
        }
        QPushButton#btnRowSave:checked:hover {
            background-color: #16A34A;
        }

        QPushButton#btnSave {
            background-color: #22C55E;
            color: white;
            font-weight: bold;
            font-size: 14px;
            border-radius: 8px;
            border: none;
        }
        QPushButton#btnSave:hover { background-color: #16A34A; }
    )");
}
