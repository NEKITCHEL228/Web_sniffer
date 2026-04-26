#ifndef UI_H
#define UI_H

#include <QMainWindow>

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

    void setInterfaceError(bool hasError);

private slots:
    void onStartClicked();
    void onStopClicked();
    void onInterfaceChanged();

private:
    void setupUI();
    void applyStyles();

    QComboBox *comboInterface;
    QLineEdit *filterInput;
    QPushButton *btnStart;
    QPushButton *btnStop;
    QTableWidget *packetTable;

    SnifferFacade *facade;
};
#endif // UI_H
