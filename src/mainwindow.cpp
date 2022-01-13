#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include <l8w8jwt/encode.h>
#include <l8w8jwt/decode.h>
#include <l8w8jwt/version.h>

#include <QDateTime>
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
    //if (ok && !text.isEmpty())

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

void MainWindow::on_pushButtonDecode_clicked()
{
    // TODO: implement this
}
