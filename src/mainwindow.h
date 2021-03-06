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
    explicit MainWindow(QWidget* parent = nullptr);
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

    void on_textEditDecodeJwt_textChanged();

    void on_textEditSignatureVerificationKey_textChanged();

    void on_textEditSigningKey_textChanged();

    void on_pushButtonShowSigningKeyPassword_pressed();

    void on_pushButtonShowSigningKeyPassword_released();

    void onChangedFocus(QWidget*, QWidget*);

    void on_pushButtonClearKeyPair_clicked();

    void on_pushButtonGenerateKeyPair_clicked();

    void on_textEditKeygenPublicKey_textChanged();

    void on_textEditKeygenPrivateKey_textChanged();

    void on_comboBoxKeygenKeyType_currentIndexChanged(int index);

private:
    Ui::MainWindow* ui;

    void loadSettings();
    void ensureDateTimeFieldsValidity();
    void generateRsaKeyPair();
    void generateEddsaKeyPair();
    void generateEcdsaKeyPair(int keyType);
    QString sanitizeCustomClaimValue(QString);
    QString desanitizeCustomClaimValue(QString);
};
#endif // MAINWINDOW_H
