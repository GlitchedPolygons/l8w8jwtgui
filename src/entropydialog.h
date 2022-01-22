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
    bool isModified() const { return modified; }

protected:
    void mousePressEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;

private:
    Ui::EntropyDialog* ui;

    void drawLineTo(const QPoint& endPoint);
    void resizeImage(QImage* image, const QSize& newSize);

    unsigned char entropy[32];
    bool modified = false;
    bool scribbling = false;
    int myPenWidth = 1;
    QColor myPenColor = Qt::blue;
    QImage image;
    QPoint lastPoint;
};

#endif // ENTROPYDIALOG_H
