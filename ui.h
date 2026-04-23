#ifndef UI_H
#define UI_H

#include <QMainWindow>

class QPushButton;
class QLineEdit;
class QTableView;
class SnifferFacade;

class UI : public QMainWindow
{
    Q_OBJECT

public:
    UI(QWidget *parent = nullptr);
    ~UI();

private slots:
    void onStartClicked();
    void onStopClicked();

private:
    void setupUI();

    QPushButton *btnStart;
    QPushButton *btnStop;
    QLineEdit *filterInput;
    QTableView *packetTable;

    SnifferFacade *facade;
};
#endif // UI_H
