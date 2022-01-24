#include "entropydialog.h"
#include "./ui_entropydialog.h"
#include "constants.h"

#include <QPainter>
#include <QDateTime>
#include <QMouseEvent>

#include <ed25519.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <mbedtls/platform_util.h>

// A lot of inspiration for this class was taken from the official Qt Scribble example (https://doc.qt.io/qt-5/qtwidgets-widgets-scribble-example.html)

EntropyDialog::EntropyDialog(QWidget* parent) : QDialog { parent }, ui(new Ui::EntropyDialog)
{
    ui->setupUi(this);
    ui->progressBar->setTextVisible(false);

    entropyBuffer.reserve(1024);
    ed25519_create_seed(entropy);

    addTimestampToEntropyBuffer();
}

void EntropyDialog::addTimestampToEntropyBuffer()
{
    size_t entropyBase64Length = 0;
    char entropyBase64[(sizeof(entropy) * 2) + 1] = { 0x00 };
    mbedtls_base64_encode((unsigned char*)entropyBase64, sizeof(entropyBase64), &entropyBase64Length, entropy, sizeof(entropy));

    entropyBuffer += QString(entropyBase64);
    entropyBuffer += QDateTime::currentDateTimeUtc().toString(Qt::DateFormat::ISODateWithMs);

    mbedtls_platform_zeroize(entropyBase64, sizeof(entropyBase64));
    mbedtls_platform_zeroize(&entropyBase64Length, sizeof(entropyBase64Length));
}

void EntropyDialog::flushEntropyBuffer()
{
    addTimestampToEntropyBuffer();

    QByteArray entropyUtf8 = entropyBuffer.toUtf8();
    mbedtls_sha256(reinterpret_cast<const unsigned char*>(entropyUtf8.data()), entropyUtf8.size(), entropy, 0);

#ifndef NDEBUG
    size_t entropyBase64Length = 0;
    char entropyBase64[(sizeof(entropy) * 2) + 1] = { 0x00 };
    mbedtls_base64_encode((unsigned char*)entropyBase64, sizeof(entropyBase64), &entropyBase64Length, entropy, sizeof(entropy));

    printf("\nCollected entropy SHA256: %s\n", entropyBase64);
#endif

    mbedtls_platform_zeroize(entropyUtf8.data(), entropyUtf8.size());
    mbedtls_platform_zeroize(entropyBuffer.data(), entropyBuffer.capacity());

    entropyUtf8.clear();
    entropyBuffer.clear();
}

void EntropyDialog::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton && ui->frame->underMouse())
    {
        addTimestampToEntropyBuffer();
        lastPoint = event->pos();
        scribbling = true;
    }
}

void EntropyDialog::mouseMoveEvent(QMouseEvent* event)
{
    if ((event->buttons() & Qt::LeftButton) && scribbling)
    {
        drawLineTo(event->pos());
    }
}

void EntropyDialog::mouseReleaseEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton && scribbling)
    {
        drawLineTo(event->pos());
        flushEntropyBuffer();
        scribbling = false;
    }

    repaint();
}

void EntropyDialog::drawLineTo(const QPoint& endPoint)
{
    if (!scribbling || !ui->frame->geometry().contains(endPoint))
    {
        return;
    }

    QPainter painter(&image);
    painter.setPen(QPen(penColor, penWidth, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.drawLine(lastPoint, endPoint);

    QString entropyString = QString("%1,%2,%3,%4").arg(lastPoint.x()).arg(lastPoint.y()).arg(endPoint.x()).arg(endPoint.y());
    entropyBuffer += entropyString;
    collectedEntropy += entropyString.size();

    ui->progressBar->setValue(static_cast<int>(collectedEntropy));
    ui->progressBar->repaint();

    if (entropyBuffer.size() > Constants::minEntropyToCollect * 2)
    {
        flushEntropyBuffer();
    }

    if (collectedEntropy > Constants::minEntropyToCollect && !ui->buttonBox->isEnabled())
    {
        ui->buttonBox->setEnabled(true);
    }

    const int rad = (penWidth / 2) + 2;
    update(QRect(lastPoint, endPoint).normalized().adjusted(-rad, -rad, +rad, +rad));
    lastPoint = endPoint;
}

void EntropyDialog::resizeEvent(QResizeEvent* event)
{
    if (width() > image.width() || height() > image.height())
    {
        const int newWidth = qMax(width() + 128, image.width());
        const int newHeight = qMax(height() + 128, image.height());
        resizeImage(&image, QSize(newWidth, newHeight));
        update();
    }

    QWidget::resizeEvent(event);
}

void EntropyDialog::resizeImage(QImage* image, const QSize& newSize)
{
    if (image->size() == newSize)
    {
        return;
    }

    QImage newImage(newSize, QImage::Format_RGB32);
    newImage.fill(QColor(32, 32, 32, 0)); // TODO: take all colors for this entropy dialog from theme if available!

    QPainter painter(&newImage);
    painter.drawImage(QPoint(0, 0), *image);

    *image = newImage;
}

void EntropyDialog::paintEvent(QPaintEvent* event)
{
    QPainter painter(this);
    QRect dirtyRect = event->rect();
    painter.drawImage(dirtyRect, image, dirtyRect);
}

void EntropyDialog::getCollectedEntropy(unsigned char outEntropy32B[32])
{
    if (outEntropy32B == nullptr)
    {
        return;
    }

    flushEntropyBuffer();
    memcpy(outEntropy32B, entropy, 32);
}
