#ifndef UI_H
#define UI_H

#include <QMainWindow>
#include <memory>
#include <vector>
#include "packet.h"
#include "filterwidget.h"
#include "filterparser.h"

#include <QStackedWidget>
#include <QVBoxLayout>

class QPushButton;
class QLineEdit;
class QTableWidget;
class QComboBox;
class SnifferFacade;
class QTextEdit;
class QLabel;

enum class AnalysisCategory {
    Encrypted,
    Unencrypted,
    DNS,
    SYNFlood,
    SuspiciousPorts,
    DoS
};

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
    void showPacketDetails(int row, int column);
    void showCaptureView();
    void showAnalysisView();
    void updateAnalysisDashboard();
    void showAnalysisTableForCategory(int categoryInt);
    void showAnalysisDashboard();
    void onAnalysisTableDoubleClicked(int row, int column);

private:
    void setupUI();
    void applyStyles();
    void setupButtonContent(QPushButton* btn, const QString& text, const QString& iconPath);
    void addPacketToTable(std::shared_ptr<Packet> packet);
    void addPacketToAnalysisTable(std::shared_ptr<Packet> packet);
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

    // Top Nav
    QPushButton *btnNavCapture;
    QPushButton *btnNavAnalysis;

    // Stacked Widget
    QStackedWidget *stackedWidget;
    QWidget *captureWidget;
    QWidget *analysisWidget;
    QWidget *packetDetailsWidget;

    // Analysis UI
    QStackedWidget *analysisStackedWidget;
    QWidget *analysisDashboard;
    QWidget *analysisTableContainer;
    QTableWidget *analysisTable;
    QLabel *lblNoAnomalies;
    QVBoxLayout *analysisDashboardLayout;

    // Abstract blocks
    QPushButton* createAnalysisBlock(const QString& title, const QString& value, const QString& color, int category);

    // Packet Details UI
    QLabel *lblDetailSummary;
    QTextEdit *textRawData;

    QString lastInterface;
    std::unique_ptr<SnifferFacade> facade;

    std::vector<std::shared_ptr<Packet>> allPackets;
    std::vector<std::shared_ptr<Packet>> displayedPackets;
    std::vector<std::shared_ptr<Packet>> analysisDisplayedPackets;
    AnalysisCategory currentAnalysisCategory;

    SimpleFilterData currentFilter;
    std::shared_ptr<ASTNode> currentStringFilter;
    void applyStringFilter();

    QWidget *prevWidgetForDetails; // keep track of where to return
    void backFromPacketDetails();
    void showPacketDetailsWithPacket(std::shared_ptr<Packet> packet, int displayRow);
};
#endif
