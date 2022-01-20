#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include "constants.h"

#include <l8w8jwt/base64.h>
#include <l8w8jwt/encode.h>
#include <l8w8jwt/decode.h>
#include <l8w8jwt/version.h>

#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>
#include <mbedtls/x509.h>
#include <mbedtls/rsa.h>
#include <mbedtls/platform.h>

#include <QTimer>
#include <QDateTime>
#include <QSettings>
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

    loadSettings();

    on_textEditSigningKey_textChanged();
    on_textEditEncodeOutput_textChanged();
    on_textEditDecodeOutput_textChanged();
    on_textEditKeygenPublicKey_textChanged();
    on_listWidgetCustomClaims_itemSelectionChanged();
}

MainWindow::~MainWindow()
{
    QSettings settings;

    settings.setValue(Constants::Settings::saveClaimsOnQuit, QVariant(ui->checkBoxSaveClaims->isChecked()));
    settings.setValue(Constants::Settings::saveWindowSizeOnQuit, QVariant(ui->checkBoxSaveWindowSizeOnQuit->isChecked()));
    settings.setValue(Constants::Settings::selectTextOnFocus, QVariant(ui->checkBoxSelectTextFieldContentOnFocus->isChecked()));

    const bool saveWindow = ui->checkBoxSaveWindowSizeOnQuit->isChecked();
    const bool saveClaims = ui->checkBoxSaveClaims->isChecked();

    if (saveWindow)
    {
        settings.setValue(Constants::Settings::windowWidth, QVariant(width()));
        settings.setValue(Constants::Settings::windowHeight, QVariant(height()));
    }

    if (saveClaims)
    {
        settings.setValue(Constants::Settings::issuer, QVariant(QString(ui->lineEditIssuer->text().toUtf8().toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals))));
        settings.setValue(Constants::Settings::subject, QVariant(QString(ui->lineEditSubject->text().toUtf8().toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals))));
        settings.setValue(Constants::Settings::audience, QVariant(QString(ui->lineEditAudience->text().toUtf8().toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals))));

        QString customClaims;
        customClaims.reserve(512);

        for (int i = 0; i < ui->listWidgetCustomClaims->count(); ++i)
        {
            const QListWidgetItem* customClaimListWidgetItem = ui->listWidgetCustomClaims->item(i);
            const QString encodedClaim = customClaimListWidgetItem->text().toUtf8().toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);

            customClaims += encodedClaim;

            if (i != ui->listWidgetCustomClaims->count() - 1)
            {
                customClaims += ',';
            }
        }

        settings.setValue(Constants::Settings::customClaims, QVariant(customClaims));
    }

    delete ui;
}

static inline QString decodeClaim(QString encodedClaim)
{
    const QByteArray::FromBase64Result decodedUtf8 = QByteArray::fromBase64Encoding(encodedClaim.toUtf8(), QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals | QByteArray::AbortOnBase64DecodingErrors);
    return decodedUtf8.decodingStatus == QByteArray::Base64DecodingStatus::Ok ? decodedUtf8.decoded : QString();
}

void MainWindow::loadSettings()
{
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings settings;

    const bool saveClaims = settings.value(Constants::Settings::saveClaimsOnQuit, QVariant(true)).toBool();
    const bool saveWindow = settings.value(Constants::Settings::saveWindowSizeOnQuit, QVariant(false)).toBool();
    const bool selectTextOnFocus = settings.value(Constants::Settings::selectTextOnFocus, QVariant(true)).toBool();

    ui->checkBoxSaveClaims->setChecked(saveClaims);
    ui->checkBoxSaveWindowSizeOnQuit->setChecked(saveWindow);
    ui->checkBoxSelectTextFieldContentOnFocus->setChecked(selectTextOnFocus);

    if (saveClaims)
    {
        const QString iss = settings.value(Constants::Settings::issuer, QVariant(QString())).toString();
        const QString sub = settings.value(Constants::Settings::subject, QVariant(QString())).toString();
        const QString aud = settings.value(Constants::Settings::audience, QVariant(QString())).toString();
        const QString customClaims = settings.value(Constants::Settings::customClaims, QVariant(QString())).toString();

        ui->lineEditIssuer->setText(decodeClaim(iss));
        ui->lineEditSubject->setText(decodeClaim(sub));
        ui->lineEditAudience->setText(decodeClaim(aud));

        for (QString customClaim : customClaims.split(','))
        {
            const QString decodedClaim = decodeClaim(customClaim);

            if (decodedClaim.isEmpty())
                continue;

            ui->listWidgetCustomClaims->addItem(decodedClaim);
        }
    }

    if (saveWindow)
    {
        const int w = settings.value(Constants::Settings::windowWidth, QVariant(minimumSize().width())).toInt();
        const int h = settings.value(Constants::Settings::windowHeight, QVariant(minimumSize().height())).toInt();

        this->resize(w > 0 ? w : -w, h > 0 ? h : -h);
    }
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
        case 3084:
            return L8W8JWT_ALG_ED25519;
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

    QString result;
    result.reserve(256);

    decodingParams.iat_tolerance_seconds = 8;
    decodingParams.exp_tolerance_seconds = 8;
    decodingParams.nbf_tolerance_seconds = 8;
    decodingParams.validate_iat = 1;
    decodingParams.validate_exp = 1;
    decodingParams.validate_nbf = 1;
    decodingParams.verification_key = (unsigned char*)const_cast<char*>(signatureVerificationKeyUtf8.constData());
    decodingParams.verification_key_length = signatureVerificationKeyUtf8.length();

    enum l8w8jwt_validation_result validationResult = ::L8W8JWT_VALID;

    const bool decodeOnly = decodingParams.verification_key == nullptr || decodingParams.verification_key_length == 0;

    if (decodeOnly)
    {
        decodingParams.verification_key = (unsigned char*)"\0\0";
        decodingParams.verification_key_length = 1;
        result += QString("⚠ No signature verification key entered: decoding only (without performing a signature check).\n\n");
    }

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

    if (!decodeOnly)
    {
        result += QString(sigFailure ? "❌ Signature invalid.\n" : "✅ Signature valid.\n");
    }

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
    {
        QSettings settings;

        if (!settings.value(Constants::Settings::selectTextOnFocus, QVariant(true)).toBool())
        {
            return;
        }
    }

    if (newlyFocusedWidget == ui->lineEditSigningKeyPassword)
    {
        QTimer::singleShot(0, ui->lineEditSigningKeyPassword, &QLineEdit::selectAll);
    }
    else if (newlyFocusedWidget == ui->lineEditIssuer)
    {
        QTimer::singleShot(0, ui->lineEditIssuer, &QLineEdit::selectAll);
    }
    else if (newlyFocusedWidget == ui->lineEditSubject)
    {
        QTimer::singleShot(0, ui->lineEditSubject, &QLineEdit::selectAll);
    }
    else if (newlyFocusedWidget == ui->lineEditAudience)
    {
        QTimer::singleShot(0, ui->lineEditAudience, &QLineEdit::selectAll);
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
    else if (newlyFocusedWidget == ui->textEditKeygenPrivateKey)
    {
        QTimer::singleShot(0, ui->textEditKeygenPrivateKey, &QTextEdit::selectAll);
    }
    else if (newlyFocusedWidget == ui->textEditKeygenPublicKey)
    {
        QTimer::singleShot(0, ui->textEditKeygenPublicKey, &QTextEdit::selectAll);
    }
}

void MainWindow::on_pushButtonClearKeyPair_clicked()
{
    ui->textEditKeygenPrivateKey->clear();
    ui->textEditKeygenPublicKey->clear();
}

void MainWindow::generateRsaKeyPair()
{
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    static constexpr int PEM_BUFFER_SIZE = 8192;

    unsigned char* publicKeyPem = nullptr;
    unsigned char* privateKeyPem = nullptr;

    try
    {
        publicKeyPem = new unsigned char[PEM_BUFFER_SIZE];
        privateKeyPem = new unsigned char[PEM_BUFFER_SIZE];
    }
    catch (const std::bad_alloc& exception)
    {
        QMessageBox error;
        error.setIcon(QMessageBox::Critical);
        error.setText(QString("❌ Failed to allocate memory for holding the PEM-formatted output RSA key pairs! Are we out of memory? Uh ohhh...."));
        error.exec();

        QCoreApplication::quit();
        std::this_thread::sleep_for(std::chrono::milliseconds(256));
        throw exception;
    }

    memset(publicKeyPem, 0x00, PEM_BUFFER_SIZE);
    memset(privateKeyPem, 0x00, PEM_BUFFER_SIZE);

    const char* pers = "rsa_genkey"; // TODO: create entropy collection dialog!

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_pk_init(&pk);

    int r = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
    if (r != 0)
    {
        ui->textEditKeygenPublicKey->setText(QString("❌ Failed to generate RSA key pair! \"mbedtls_ctr_drbg_seed\" returned error code: %1").arg(r));
        goto exit;
    }

    r = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (r != 0)
    {
        ui->textEditKeygenPublicKey->setText(QString("❌ Failed to generate RSA key pair! \"mbedtls_pk_setup\" returned error code: %1").arg(r));
        goto exit;
    }

    r = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr_drbg, 4096, 65537);
    if (r != 0)
    {
        ui->textEditKeygenPublicKey->setText(QString("❌ Failed to generate RSA key pair! \"mbedtls_rsa_gen_key\" returned error code: %1").arg(r));
        goto exit;
    }

    r = mbedtls_rsa_check_pubkey(mbedtls_pk_rsa(pk));
    if (r != 0)
    {
        ui->textEditKeygenPublicKey->setText(QString("❌ Failed to generate RSA key pair! \"mbedtls_rsa_check_pubkey\" returned error code: %1").arg(r));
        goto exit;
    }

    r = mbedtls_rsa_check_privkey(mbedtls_pk_rsa(pk));
    if (r != 0)
    {
        ui->textEditKeygenPublicKey->setText(QString("❌ Failed to generate RSA key pair! \"mbedtls_rsa_check_privkey\" returned error code: %1").arg(r));
        goto exit;
    }

    r = mbedtls_pk_write_pubkey_pem(&pk, publicKeyPem, PEM_BUFFER_SIZE);
    if (r != 0)
    {
        ui->textEditKeygenPublicKey->setText(QString("❌ Failed to generate RSA key pair! \"mbedtls_pk_write_pubkey_pem\" returned error code: %1").arg(r));
        goto exit;
    }

    r = mbedtls_pk_write_key_pem(&pk, privateKeyPem, PEM_BUFFER_SIZE);
    if (r != 0)
    {
        ui->textEditKeygenPublicKey->setText(QString("❌ Failed to generate RSA key pair! \"mbedtls_pk_write_key_pem\" returned error code: %1").arg(r));
        goto exit;
    }

    ui->textEditKeygenPrivateKey->setText(QString(reinterpret_cast<char*>(privateKeyPem)));
    ui->textEditKeygenPublicKey->setText(QString(reinterpret_cast<char*>(publicKeyPem)));

exit:
    mbedtls_pk_free(&pk);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    delete[] privateKeyPem;
    delete[] publicKeyPem;
}

void MainWindow::generateSecp256k1KeyPair()
{
    //
}

void MainWindow::on_pushButtonGenerateKeyPair_clicked()
{
    ui->textEditKeygenPublicKey->setText(QString("⏳ Generating..."));
    ui->textEditKeygenPrivateKey->clear();
    repaint();

    switch (ui->comboBoxKeygenKeyType->currentIndex())
    {
        case 0:
            generateRsaKeyPair();
            break;

            // TODO: other key types!
    }
}

void MainWindow::on_textEditKeygenPublicKey_textChanged()
{
    ui->pushButtonClearKeyPair->setEnabled(!ui->textEditKeygenPublicKey->toPlainText().isEmpty() || !ui->textEditKeygenPrivateKey->toPlainText().isEmpty());
}

void MainWindow::on_textEditKeygenPrivateKey_textChanged()
{
    ui->pushButtonClearKeyPair->setEnabled(!ui->textEditKeygenPublicKey->toPlainText().isEmpty() || !ui->textEditKeygenPrivateKey->toPlainText().isEmpty());
}

void MainWindow::on_comboBoxKeygenKeyType_currentIndexChanged(int index) { }
