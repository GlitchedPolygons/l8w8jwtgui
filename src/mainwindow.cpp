#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <l8w8jwt/base64.h>
#include <l8w8jwt/encode.h>
#include <l8w8jwt/decode.h>
#include <l8w8jwt/version.h>

#include <QTimer>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonDocument>
#include <QMessageBox>
#include <QInputDialog>

#include <chrono>
#include <thread>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    ui->dateTimeEditNotBefore->setMinimumDateTime(QDateTime::currentDateTimeUtc().addSecs(-60));
    ui->dateTimeEditExpiration->setMinimumDateTime(QDateTime::currentDateTimeUtc().addSecs(60));
    ui->dateTimeEditExpiration->setDateTime(QDateTime::currentDateTimeUtc().addSecs(600));

    ui->labelVersionNumbers->setText(QString("lib/l8w8jwt version: %1").arg(L8W8JWT_VERSION_STR));

    on_textEditSigningKey_textChanged();
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

    on_listWidgetCustomClaims_itemSelectionChanged();
}

void MainWindow::on_listWidgetCustomClaims_itemSelectionChanged()
{
    const bool listEmpty = ui->listWidgetCustomClaims->count() == 0;

    ui->pushButtonClearCustomClaims->setEnabled(!listEmpty);
    ui->pushButtonRemoveSelectedCustomClaim->setEnabled(!listEmpty);
}

QString MainWindow::sanitizeCustomClaimValue(QString value)
{
    QString trimmedValue = value.trimmed();

    if (trimmedValue.isEmpty())
    {
        return "\"\"";
    }

    bool numberType = false;

    (void)trimmedValue.toLongLong(&numberType);

    if (!numberType)
    {
        (void)trimmedValue.toDouble(&numberType);
    }

    if (numberType)
    {
        return trimmedValue.replace("\"", "");
    }

    if (trimmedValue == "true" || trimmedValue == "false" || trimmedValue == "null")
    {
        return trimmedValue;
    }

    if (trimmedValue.startsWith("\"") && trimmedValue.endsWith("\""))
    {
        const size_t trimmedValueLength = trimmedValue.count();
        trimmedValue = trimmedValue.right(trimmedValueLength - 1).left(trimmedValueLength - 2);
    }

    return QString("\"%1\"").arg(trimmedValue.replace("\"", "\\\""));
}

void MainWindow::on_pushButtonAddCustomClaim_clicked()
{
    bool ok;
    QString text = QInputDialog::getText(this, "Add custom claim", "Enter your desired custom claim's name here (e.g. \"jti\", \"uid\" or something like that).\n", QLineEdit::Normal, "", &ok);

    if (ok && !text.isEmpty())
    {
        const QString claimName = text.trimmed().replace("\"", "");
        text = QInputDialog::getText(this, "Add custom claim", "Enter your desired custom claim's value here.\n\nThis may be a number, a string value, a boolean or even null.\n", QLineEdit::Normal, "", &ok);

        if (ok)
        {
            const QString claimValue = sanitizeCustomClaimValue(text);

            ui->listWidgetCustomClaims->addItem(QString("\"%1\": %2").arg(claimName).arg(claimValue));
            on_listWidgetCustomClaims_itemSelectionChanged();
        }
    }
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
    int r = -1;
    struct l8w8jwt_encoding_params encodingParams = { 0x00 };

    encodingParams.iat = time(nullptr);
    encodingParams.alg = ui->comboBoxAlgo->currentIndex();

    const QDateTime exp = ui->dateTimeEditExpiration->dateTime();
    const QDateTime nbf = ui->dateTimeEditNotBefore->dateTime();

    const QString iss = ui->lineEditIssuer->text();
    QByteArray issUtf8 = iss.toUtf8();

    const QString sub = ui->lineEditSubject->text();
    QByteArray subUtf8 = sub.toUtf8();

    const QString aud = ui->lineEditAudience->text();
    QByteArray audUtf8 = aud.toUtf8();

    const QString signingKey = ui->textEditSigningKey->toPlainText();
    QByteArray signingKeyUtf8 = signingKey.toUtf8();

    const QString signingKeyPassword = ui->lineEditSigningKeyPassword->text();
    QByteArray signingKeyPasswordUtf8 = signingKeyPassword.toUtf8();

    encodingParams.secret_key = reinterpret_cast<unsigned char*>(signingKeyUtf8.data());
    encodingParams.secret_key_length = signingKeyUtf8.length();

    encodingParams.exp = exp.toSecsSinceEpoch();
    encodingParams.nbf = nbf.toSecsSinceEpoch();

    if (!signingKeyPassword.isEmpty())
    {
        encodingParams.secret_key_pw = reinterpret_cast<unsigned char*>(signingKeyPasswordUtf8.data());
        encodingParams.secret_key_pw_length = signingKeyPasswordUtf8.length();
    }

    if (!iss.isEmpty())
    {
        encodingParams.iss = issUtf8.data();
        encodingParams.iss_length = issUtf8.length();
    }

    if (!sub.isEmpty())
    {
        encodingParams.sub = subUtf8.data();
        encodingParams.sub_length = subUtf8.length();
    }

    if (!aud.isEmpty())
    {
        encodingParams.aud = audUtf8.data();
        encodingParams.aud_length = audUtf8.length();
    }

    char* output = nullptr;
    size_t outputLength = 0;

    encodingParams.out = &output;
    encodingParams.out_length = &outputLength;

    if (ui->listWidgetCustomClaims->count() != 0)
    {
        try
        {
            encodingParams.additional_payload_claims = new struct l8w8jwt_claim[ui->listWidgetCustomClaims->count()];
            encodingParams.additional_payload_claims_count = ui->listWidgetCustomClaims->count();

            for (int i = 0; i < ui->listWidgetCustomClaims->count(); ++i)
            {
                const QListWidgetItem* customClaimListWidgetItem = ui->listWidgetCustomClaims->item(i);
                const QStringList customClaimKvp = customClaimListWidgetItem->text().split(": ");

                if (customClaimKvp.length() != 2)
                {
                    throw std::exception("L8W8JWT GUI custom claim QListWidget entry string format requirement circumvented and thus infringed! These MUST be key-value pairs separated by \": \" for a valid payload to be written and signed!");
                }

                const QString customClaimKey = customClaimKvp[0];
                const QString customClaimValue = customClaimKvp[1];

                QByteArray customClaimKeyUtf8 = customClaimKey.toUtf8();
                QByteArray customClaimValueUtf8 = customClaimValue.toUtf8();

                struct l8w8jwt_claim& customClaim = encodingParams.additional_payload_claims[i];

                customClaim.type = 7;

                customClaim.key_length = customClaimKeyUtf8.length() - 2;
                customClaim.key = new char[customClaim.key_length + 1];
                strncpy(customClaim.key, customClaimKeyUtf8.data() + 1, customClaim.key_length);
                customClaim.key[customClaim.key_length] = 0x00;

                customClaim.value_length = customClaimValueUtf8.length();
                customClaim.value = new char[customClaim.value_length + 1];
                strncpy(customClaim.value, customClaimValueUtf8.data(), customClaim.value_length);
                customClaim.value[customClaim.value_length] = 0x00;
            }
        }
        catch (const std::bad_alloc& exception)
        {
            QMessageBox error;
            error.setIcon(QMessageBox::Critical);
            error.setText(QString("❌ Failed to allocate memory for the custom claims to feed into l8w8jwt's encode function parameters struct! Are we OOM? Uh ohhh...."));
            error.exec();

            QCoreApplication::quit();
            std::this_thread::sleep_for(std::chrono::milliseconds(256));
            throw exception;
        }
    }

    r = l8w8jwt_encode(&encodingParams);

    switch (r)
    {
        case L8W8JWT_SUCCESS: {
            ui->textEditEncodeOutput->setText(QString(output));
            break;
        }
        case L8W8JWT_OUT_OF_MEM: {
            ui->textEditEncodeOutput->setText(QString("❌ Encoding and/or signing token failed: OUT OF MEMORY! Uh oh..."));
            break;
        }
        case L8W8JWT_KEY_PARSE_FAILURE: {
            ui->textEditEncodeOutput->setText(QString("❌ Failed to parse jwt signing key!"));
            break;
        }
        case L8W8JWT_WRONG_KEY_TYPE: {
            ui->textEditEncodeOutput->setText(QString("❌ Failure to sign token: wrong/invalid signing key type! \"l8w8jwt_encode\" returned: %1").arg(r));
            break;
        }
        case L8W8JWT_SIGNATURE_CREATION_FAILURE: {
            ui->textEditEncodeOutput->setText(QString("❌ Failure to sign token! \"l8w8jwt_encode\" returned: %1").arg(r));
            break;
        }
        case L8W8JWT_SHA2_FAILURE: {
            ui->textEditEncodeOutput->setText(QString("❌ Failed to hash jwt header + payload with the appropriate SHA-2 function; wtf! \"l8w8jwt_encode\" returned: %1").arg(r));
            break;
        }
        case L8W8JWT_BASE64_FAILURE: {
            ui->textEditEncodeOutput->setText(QString("❌ Failure to base64 url-encode one or more token segments! \"l8w8jwt_encode\" returned: %1").arg(r));
            break;
        }
        default: {
            ui->textEditEncodeOutput->setText(QString("❌ Encoding and/or signing the token failed. \"l8w8jwt_encode\" returned: %1").arg(r));
            break;
        }
    }

    l8w8jwt_free(output);

    for (size_t i = 0; i < encodingParams.additional_payload_claims_count; ++i)
    {
        delete[] encodingParams.additional_payload_claims[i].key;
        delete[] encodingParams.additional_payload_claims[i].value;
    }

    delete[] encodingParams.additional_payload_claims;
}

static inline int jwtAlgoFromString(const QString alg)
{
    const uint16_t crc16 = qChecksum(alg.toUtf8());

    switch (crc16)
    {
        case 2839:
            return L8W8JWT_ALG_HS256;
        case 49825:
            return L8W8JWT_ALG_HS384;
        case 42582:
            return L8W8JWT_ALG_HS512;
        case 62463:
            return L8W8JWT_ALG_RS256;
        case 14921:
            return L8W8JWT_ALG_RS384;
        case 24254:
            return L8W8JWT_ALG_RS512;
        case 58743:
            return L8W8JWT_ALG_PS256;
        case 11547:
            return L8W8JWT_ALG_PS384;
        case 18486:
            return L8W8JWT_ALG_PS512;
        case 30563:
            return L8W8JWT_ALG_ES256;
        case 48853:
            return L8W8JWT_ALG_ES384;
        case 55842:
            return L8W8JWT_ALG_ES512;
        case 23877:
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

    if (decodingParams.alg == -1)
    {
        ui->textEditDecodeOutput->setText("❌ Failed to decode: invalid or unrecognized jwt \"alg\" claim value inside header segment!");
        return;
    }

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

    result += QString(sigFailure ? "❌ Signature invalid.\n" : "✅ Signature valid.\n");

    if (!payloadJsonDocument["iat"].isUndefined())
    {
        result += QString(iatFailure ? "❌ iat: Emission timestamp invalid.\n" : "✅ iat: Emission timestamp verified.\n");
    }

    if (!payloadJsonDocument["exp"].isUndefined())
    {
        result += QString(expFailure ? "❌ exp: Token expired or expiration date value invalid.\n" : "✅ exp: Token not expired.\n");
    }

    if (!payloadJsonDocument["nbf"].isUndefined())
    {
        result += QString(nbfFailure ? "❌ nbf: Token not yet valid or \"nbf\" claim value unrecognized/invalid.\n" : "✅ nbf: Verified.\n");
    }

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

void MainWindow::on_textEditSigningKey_textChanged()
{
    ui->pushButtonEncodeAndSign->setEnabled(!ui->textEditSigningKey->toPlainText().isEmpty());
}

void MainWindow::on_pushButtonShowSigningKeyPassword_pressed()
{
    ui->lineEditSigningKeyPassword->setEchoMode(QLineEdit::EchoMode::Normal);
    ui->pushButtonShowSigningKeyPassword->setText("Hide");
}

void MainWindow::on_pushButtonShowSigningKeyPassword_released()
{
    ui->lineEditSigningKeyPassword->setEchoMode(QLineEdit::EchoMode::Password);
    ui->pushButtonShowSigningKeyPassword->setText("Show");
}

void MainWindow::onChangedFocus(QWidget*, QWidget* newlyFocusedWidget)
{
    if (newlyFocusedWidget == ui->lineEditSigningKeyPassword)
    {
        QTimer::singleShot(0, ui->lineEditSigningKeyPassword, &QLineEdit::selectAll);
    }
    else if (newlyFocusedWidget == ui->textEditSigningKey)
    {
        QTimer::singleShot(0, ui->textEditSigningKey, &QTextEdit::selectAll);
    }
    else if (newlyFocusedWidget == ui->textEditEncodeOutput)
    {
        QTimer::singleShot(0, ui->textEditEncodeOutput, &QTextEdit::selectAll);
    }
    else if (newlyFocusedWidget == ui->textEditDecodeJwt)
    {
        QTimer::singleShot(0, ui->textEditDecodeJwt, &QTextEdit::selectAll);
    }
    else if (newlyFocusedWidget == ui->textEditSignatureVerificationKey)
    {
        QTimer::singleShot(0, ui->textEditSignatureVerificationKey, &QTextEdit::selectAll);
    }
}
