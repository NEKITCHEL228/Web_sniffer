#ifndef UI_H
#define UI_H

#include <QMainWindow>
#include <memory>
#include "packet.h"

class QPushButton;
class QLineEdit;
class QTableWidget;
class QComboBox;
class SnifferFacade;

class UI : public QMainWindow
{
    Q_OBJECT

public:
    UI(QWidget *parent = nullptr);
    ~UI();

public slots:
    void onPacketReceived(std::shared_ptr<Packet> packet);

private slots:
    void onStartClicked();
    void onStopClicked();
    void onInterfaceChanged();
    void onRefreshInterfaces();

private:
    void setupUI();
    void applyStyles();
    void setupButtonContent(QPushButton* btn, const QString& text, const QString& iconPath);
    void addPacketToTable(std::shared_ptr<Packet> packet);

    QComboBox *comboInterface;
    QLineEdit *filterInput;
    QPushButton *btnStart;
    QPushButton *btnStop;
    QPushButton *btnRefreshInterfaces;
    QTableWidget *packetTable;

    std::unique_ptr<SnifferFacade> facade;
};
#endif
