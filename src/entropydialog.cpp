#include "entropydialog.h"
#include "./ui_entropydialog.h"

EntropyDialog::EntropyDialog(QWidget* parent) : QDialog { parent }, ui(new Ui::EntropyDialog)
{
    ui->setupUi(this);
}

void EntropyDialog::mousePressEvent(QMouseEvent* event)
{
    // todo
}

void EntropyDialog::mouseMoveEvent(QMouseEvent* event)
{
    // todo
}

void EntropyDialog::mouseReleaseEvent(QMouseEvent* event)
{
    // todo
}

void EntropyDialog::paintEvent(QPaintEvent* event)
{
    // todo
}

void EntropyDialog::getCollectedEntropy(unsigned char outEntropy32B[32])
{
    if (outEntropy32B == nullptr)
    {
        return;
    }

    memcpy(outEntropy32B, entropy, 32);
}
