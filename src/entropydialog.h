#ifndef ENTROPYDIALOG_H
#define ENTROPYDIALOG_H

#include <QWidget>
#include <QDialog>

QT_BEGIN_NAMESPACE
namespace Ui {
class EntropyDialog;
}
QT_END_NAMESPACE

class EntropyDialog : public QDialog
{
    Q_OBJECT

public:
    explicit EntropyDialog(QWidget* parent = nullptr);
    void getCollectedEntropy(unsigned char outEntropy32B[32]);

protected:
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void paintEvent(QPaintEvent* event) override;

private:
    Ui::EntropyDialog* ui;
    unsigned char entropy[32];
};

#endif // ENTROPYDIALOG_H
