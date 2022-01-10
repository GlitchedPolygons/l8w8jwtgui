#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

private slots:
    void on_pushButtonNotBeforeAutoSet_clicked();

    void on_pushButtonExpirationAutoSet_clicked();

    void on_pushButtonClearCustomClaims_clicked();

    void on_pushButtonRemoveSelectedCustomClaim_clicked();

    void on_listWidgetCustomClaims_itemSelectionChanged();

    void on_pushButtonAddCustomClaim_clicked();

    void on_pushButtonClearEncodeOutput_clicked();

    void on_pushButtonClearDecodeOutput_clicked();

    void on_textEditDecodeOutput_textChanged();

    void on_textEditEncodeOutput_textChanged();

    void on_pushButtonEncodeAndSign_clicked();

    void on_pushButtonDecode_clicked();

private:
    Ui::MainWindow* ui;

    void ensureDateTimeFieldsValidity();
};
#endif // MAINWINDOW_H
