#ifndef UI_H
#define UI_H

#include <QMainWindow>
#include <QLabel>
#include <memory>
#include <vector>
#include "packet.h"
#include "filterwidget.h"
#include "filterparser.h"

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
    void applySimpleFilter(SimpleFilterData data);

private:
    void setupUI();
    void applyStyles();
    void setupButtonContent(QPushButton* btn, const QString& text, const QString& iconPath);
    void addPacketToTable(std::shared_ptr<Packet> packet);
    bool isPacketMatching(std::shared_ptr<Packet> packet);
    void redrawTable();
    void updateStatistics();

    QComboBox *comboInterface;
    QLineEdit *filterInput;
    QPushButton *btnStart;
    QPushButton *btnStop;
    QPushButton *btnClearTable;
    QTableWidget *packetTable;
    FilterWidget *filterWidget;
    QLabel *lblStatistics;

    QString lastInterface;
    std::unique_ptr<SnifferFacade> facade;

    std::vector<std::shared_ptr<Packet>> allPackets;
    SimpleFilterData currentFilter;
    std::shared_ptr<ASTNode> currentStringFilter;
    void applyStringFilter();
};
#endif
