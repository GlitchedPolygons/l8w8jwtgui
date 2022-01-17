#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <l8w8jwt/base64.h>
#include <l8w8jwt/encode.h>
#include <l8w8jwt/decode.h>
#include <l8w8jwt/version.h>

#include <QDateTime>
#include <QJsonObject>
#include <QJsonDocument>
#include <QInputDialog>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ui->dateTimeEditNotBefore->setMinimumDateTime(QDateTime::currentDateTimeUtc().addSecs(-60));
    ui->dateTimeEditExpiration->setMinimumDateTime(QDateTime::currentDateTimeUtc().addSecs(60));
    ui->dateTimeEditExpiration->setDateTime(QDateTime::currentDateTimeUtc().addSecs(600));

    ui->labelVersionNumbers->setText(QString("lib/l8w8jwt version: %1").arg(L8W8JWT_VERSION_STR));

    on_textEditEncodeOutput_textChanged();
    on_textEditDecodeOutput_textChanged();
    on_listWidgetCustomClaims_itemSelectionChanged();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButtonNotBeforeAutoSet_clicked()
{
    ui->dateTimeEditNotBefore->setDateTime(QDateTime::currentDateTimeUtc().addSecs(-60));
}

void MainWindow::on_pushButtonExpirationAutoSet_clicked()
{
    ui->dateTimeEditExpiration->setDateTime(QDateTime::currentDateTimeUtc().addSecs(600));
}

void MainWindow::ensureDateTimeFieldsValidity()
{
    if (ui->dateTimeEditExpiration->dateTime() < QDateTime::currentDateTimeUtc().addSecs(60))
    {
        on_pushButtonExpirationAutoSet_clicked();
    }

    if (ui->dateTimeEditNotBefore->dateTime() < QDateTime::currentDateTimeUtc().addSecs(-60))
    {
        on_pushButtonNotBeforeAutoSet_clicked();
    }
}

void MainWindow::on_pushButtonClearCustomClaims_clicked()
{
    ui->listWidgetCustomClaims->clear();
    on_listWidgetCustomClaims_itemSelectionChanged();
}

void MainWindow::on_pushButtonRemoveSelectedCustomClaim_clicked()
{
    for (QListWidgetItem* selectedItem : ui->listWidgetCustomClaims->selectedItems())
    {
        delete ui->listWidgetCustomClaims->takeItem(ui->listWidgetCustomClaims->row(selectedItem));
    }
}

void MainWindow::on_listWidgetCustomClaims_itemSelectionChanged()
{
    const bool listEmpty = ui->listWidgetCustomClaims->items(nullptr).isEmpty();

    ui->pushButtonClearCustomClaims->setEnabled(!listEmpty);
    ui->pushButtonRemoveSelectedCustomClaim->setEnabled(!listEmpty);
}

void MainWindow::on_pushButtonAddCustomClaim_clicked()
{
    bool ok;
    QString text = QInputDialog::getText(this, "Add custom claim", "Enter your desired custom claim here in the following format:\n\nclaim=value\n\nFor string types that would be:\n\nclaim=\"value\"\n", QLineEdit::Normal, "", &ok);
    // if (ok && !text.isEmpty())
}

void MainWindow::on_pushButtonClearEncodeOutput_clicked()
{
    ui->textEditEncodeOutput->clear();
}

void MainWindow::on_pushButtonClearDecodeOutput_clicked()
{
    ui->textEditDecodeOutput->clear();
}

void MainWindow::on_textEditDecodeOutput_textChanged()
{
    ui->pushButtonClearDecodeOutput->setEnabled(!ui->textEditDecodeOutput->toPlainText().isEmpty());
}

void MainWindow::on_textEditEncodeOutput_textChanged()
{
    ui->pushButtonClearEncodeOutput->setEnabled(!ui->textEditEncodeOutput->toPlainText().isEmpty());
}

void MainWindow::on_pushButtonEncodeAndSign_clicked()
{
    // TODO: implement this and only add the standard claims that are also not null or empty in the GUI
}

static inline int jwtAlgoFromString(const QString alg)
{
    const uint16_t crc16 = qChecksum(alg.toUtf8());

    switch (crc16)
    {
        case 60318:
            return L8W8JWT_ALG_HS256;
        case 35504:
            return L8W8JWT_ALG_HS384;
        case 57934:
            return L8W8JWT_ALG_HS512;
        case 43370:
            return L8W8JWT_ALG_RS256;
        case 51268:
            return L8W8JWT_ALG_RS384;
        case 41146:
            return L8W8JWT_ALG_RS512;
        case 60905:
            return L8W8JWT_ALG_PS256;
        case 36039:
            return L8W8JWT_ALG_PS384;
        case 58425:
            return L8W8JWT_ALG_PS512;
        case 51940:
            return L8W8JWT_ALG_ES256;
        case 43978:
            return L8W8JWT_ALG_ES384;
        case 49972:
            return L8W8JWT_ALG_ES512;
        case 26025:
            return L8W8JWT_ALG_ES256K;
        default:
            return -1;
    }
}

void MainWindow::on_pushButtonDecode_clicked()
{
    const QString jwt = ui->textEditDecodeJwt->toPlainText();
    if (jwt.isEmpty())
    {
        ui->textEditDecodeOutput->setText("❌ JWT text field empty; nothing to decode!");
        return;
    }

    const QStringList segments = jwt.split('.');
    if (segments.count() != 3)
    {
        ui->textEditDecodeOutput->setText("❌ Invalid jwt format!");
        return;
    }

    l8w8jwt_decoding_params decodingParams = { 0x00 };

    const QByteArray jwtUtf8 = jwt.toUtf8();

    decodingParams.jwt = const_cast<char*>(jwtUtf8.constData());
    decodingParams.jwt_length = jwtUtf8.length();

    const QString header = segments[0];
    const QString payload = segments[1];
    const QString signature = segments[2];

    const QByteArray headerUtf8 = header.toUtf8();
    const QByteArray payloadUtf8 = payload.toUtf8();

    const QByteArray::FromBase64Result headerJsonUtf8 = QByteArray::fromBase64Encoding(headerUtf8, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    const QByteArray::FromBase64Result payloadJsonUtf8 = QByteArray::fromBase64Encoding(payloadUtf8, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);

    if (header.isEmpty() || headerJsonUtf8.decodingStatus != QByteArray::Base64DecodingStatus::Ok)
    {
        ui->textEditDecodeOutput->setText("❌ Failed to decode: invalid jwt header segment!");
        return;
    }

    if (payload.isEmpty() || payloadJsonUtf8.decodingStatus != QByteArray::Base64DecodingStatus::Ok)
    {
        ui->textEditDecodeOutput->setText("❌ Failed to decode: invalid jwt payload segment!");
        return;
    }

    const QJsonDocument headerJsonDocument = QJsonDocument::fromJson(headerJsonUtf8.decoded);
    const QJsonDocument payloadJsonDocument = QJsonDocument::fromJson(payloadJsonUtf8.decoded);

    QJsonValue alg = headerJsonDocument["alg"];

    if (!alg.isString())
    {
        ui->textEditDecodeOutput->setText("❌ Failed to decode: invalid jwt header segment!");
        return;
    }

    const QString headerJsonString = QString::fromUtf8(headerJsonUtf8.decoded);
    const QString payloadJsonString = QString::fromUtf8(payloadJsonUtf8.decoded);

    const QString signatureVerificationKey = ui->textEditSignatureVerificationKey->toPlainText().trimmed();
    const QByteArray signatureVerificationKeyUtf8 = signatureVerificationKey.toUtf8();

    decodingParams.alg = jwtAlgoFromString(alg.toString());
    decodingParams.iat_tolerance_seconds = 8;
    decodingParams.exp_tolerance_seconds = 8;
    decodingParams.nbf_tolerance_seconds = 8;
    decodingParams.validate_iat = 1;
    decodingParams.validate_exp = 1;
    decodingParams.validate_nbf = 1;
    decodingParams.verification_key = (unsigned char*)const_cast<char*>(signatureVerificationKeyUtf8.constData());
    decodingParams.verification_key_length = signatureVerificationKeyUtf8.length();

    if (decodingParams.verification_key == nullptr || decodingParams.verification_key_length == 0)
    {
        decodingParams.verification_key = (unsigned char*)"\0\0";
        decodingParams.verification_key_length = 1;

        // TODO: display a warning msg that notifies the user that no verification key was entered and that thus there is nothing to verify the signature against (it's a decode-only operation, in that case..)
    }

    enum l8w8jwt_validation_result validationResult = ::L8W8JWT_VALID;

    const int r = l8w8jwt_decode(&decodingParams, &validationResult, nullptr, nullptr);

    switch (r)
    {
        case L8W8JWT_SUCCESS: {
            break;
        }
        case L8W8JWT_OUT_OF_MEM: {
            ui->textEditDecodeOutput->setText(QString("❌ Out of memory! Uh oh..."));
            return;
        }
        case L8W8JWT_BASE64_FAILURE:
        case L8W8JWT_DECODE_FAILED_INVALID_TOKEN_FORMAT: {
            ui->textEditDecodeOutput->setText(QString("❌ Failed to decode jwt: invalid token format. Please double-check and ensure that all jwt segments are valid, base64 url-encoded JSON strings!"));
            return;
        }
        case L8W8JWT_KEY_PARSE_FAILURE: {
            ui->textEditDecodeOutput->setText(QString("❌ Failed to parse jwt verification key!"));
            return;
        }
        default: {
            ui->textEditDecodeOutput->setText(QString("❌ Failed to decode jwt! \"l8w8jwt_decode\" returned error code: %1").arg(r));
            return;
        }
    }

    const bool iatFailure = validationResult & ::L8W8JWT_IAT_FAILURE;
    const bool expFailure = validationResult & ::L8W8JWT_EXP_FAILURE;
    const bool nbfFailure = validationResult & ::L8W8JWT_NBF_FAILURE;
    const bool sigFailure = validationResult & ::L8W8JWT_SIGNATURE_VERIFICATION_FAILURE;

    QString result;
    result.reserve(256);

    result += QString(sigFailure ? "✅ Signature valid.\n" : "❌ Signature invalid.\n");
    result += QString(iatFailure ? "✅ Emission timestamp verified.\n" : "❌ Emission timestamp invalid.\n");
    result += QString(expFailure ? "✅ Token expiration date verified.\n" : "❌ Token expired or expiration date invalid.\n");
    result += QString(nbfFailure ? "✅ NBF (\"not before\") claim verified successfully.\n" : "❌ Token not yet valid or .\n");

    result += QString("\n✅ Decoded header:\n%1\n✅ Decoded payload:\n%2\n").arg(headerJsonDocument.toJson()).arg(payloadJsonDocument.toJson());

    ui->textEditDecodeOutput->setText(result);
}

void MainWindow::on_textEditDecodeJwt_textChanged()
{
    const bool decodeReady = !ui->textEditDecodeJwt->toPlainText().isEmpty();
    ui->pushButtonDecode->setEnabled(decodeReady);
}

void MainWindow::on_textEditSignatureVerificationKey_textChanged()
{
    const bool decodeReady = !ui->textEditDecodeJwt->toPlainText().isEmpty();
    ui->pushButtonDecode->setEnabled(decodeReady);
}
