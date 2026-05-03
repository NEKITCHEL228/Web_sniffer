#ifndef FILTERWIDGET_H
#define FILTERWIDGET_H

#include <QWidget>
#include <QString>

class QLineEdit;
class QPushButton;

struct SimpleFilterData {
    bool portActive = false;
    QString port;
    bool ipActive = false;
    QString ip;
    bool srcIpActive = false;
    QString srcIp;
    bool protoActive = false;
    QString proto;
};

class FilterWidget : public QWidget {
    Q_OBJECT
public:
    explicit FilterWidget(QWidget *parent = nullptr);
    SimpleFilterData getFilterData() const;

signals:
    void filtersApplied(SimpleFilterData data);

private:
    void setupUI();
    void applyStyles();

    QLineEdit *portEdit;
    QPushButton *portBtn;

    QLineEdit *ipEdit;
    QPushButton *ipBtn;

    QLineEdit *srcIpEdit;
    QPushButton *srcIpBtn;

    QLineEdit *protoEdit;
    QPushButton *protoBtn;

    QPushButton *btnSave;
};

#endif
