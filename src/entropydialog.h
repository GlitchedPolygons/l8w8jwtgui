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
    void resizeEvent(QResizeEvent* event) override;

private:
    Ui::EntropyDialog* ui;

    void flushEntropyBuffer();
    void addTimestampToEntropyBuffer();
    void drawLineTo(const QPoint& endPoint);
    void resizeImage(QImage* image, const QSize& newSize);

    unsigned char entropy[32];
    bool scribbling = false;
    int penWidth = 2;
    size_t collectedEntropy = 0;

    QImage image;
    QPoint lastPoint;
    QString entropyBuffer;
    QColor penColor = QColor(240, 248, 255);
};

#endif // ENTROPYDIALOG_H
