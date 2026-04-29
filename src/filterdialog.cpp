#include "filterdialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>

FilterDialog::FilterDialog(QWidget *parent) : QDialog(parent) {
    setupUI();
    applyStyles();
}

void FilterDialog::setupUI() {
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(30, 20, 30, 30);

    auto *title = new QLabel("Простой фильтр", this);
    title->setStyleSheet("font-size: 24px; font-weight: bold; color: white;");
    layout->addWidget(title);

    auto createEntry = [&](const QString &name) {
        layout->addSpacing(15);
        layout->addWidget(new QLabel(name, this));
        auto *edit = new QLineEdit(this);
        edit->setFixedHeight(35);
        layout->addWidget(edit);
    };

    createEntry("Фильтр по порту");
    createEntry("Фильтр по IP-адресу получателя");
    createEntry("Фильтр по протоколу");

    layout->addSpacing(30);
    auto *btnSave = new QPushButton("Сохранить", this);
    btnSave->setFixedHeight(45);
    btnSave->setStyleSheet("background-color: #22C55E; color: white; font-weight: bold;");
    layout->addWidget(btnSave);

    connect(btnSave, &QPushButton::clicked, this, &QDialog::accept);
}

void FilterDialog::applyStyles() {
    this->setStyleSheet("QDialog { background-color: #1E293B; border-radius: 12px; } QLabel { color: #94A3B8; } QLineEdit { background-color: #0F172A; border: 1px solid #334155; color: white; padding-left: 10px; }");
}
