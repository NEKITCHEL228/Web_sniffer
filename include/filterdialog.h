#ifndef FILTERDIALOG_H
#define FILTERDIALOG_H

#include <QDialog>

class FilterDialog : public QDialog {
    Q_OBJECT
public:
    explicit FilterDialog(QWidget *parent = nullptr);
private:
    void setupUI();
    void applyStyles();
};

#endif
