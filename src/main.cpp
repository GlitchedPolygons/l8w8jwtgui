#include "mainwindow.h"
#include "constants.h"

#include <QStyleFactory>
#include <QApplication>
#include <QFile>

static inline QPalette getDarkFusionPalette()
{
    QPalette palette;
    palette.setColor(QPalette::Window, QColor(53, 53, 53));
    palette.setColor(QPalette::WindowText, Qt::white);
    palette.setColor(QPalette::Disabled, QPalette::WindowText, QColor(127, 127, 127));
    palette.setColor(QPalette::Base, QColor(32, 32, 32));
    palette.setColor(QPalette::AlternateBase, QColor(66, 66, 66));
    palette.setColor(QPalette::ToolTipBase, Qt::white);
    palette.setColor(QPalette::ToolTipText, Qt::white);
    palette.setColor(QPalette::Text, Qt::white);
    palette.setColor(QPalette::Disabled, QPalette::Text, QColor(127, 127, 127));
    palette.setColor(QPalette::Dark, QColor(35, 35, 35));
    palette.setColor(QPalette::Shadow, QColor(20, 20, 20));
    palette.setColor(QPalette::Button, QColor(53, 53, 53));
    palette.setColor(QPalette::ButtonText, Qt::white);
    palette.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(127, 127, 127));
    palette.setColor(QPalette::BrightText, Qt::red);
    palette.setColor(QPalette::Link, QColor(42, 197, 218));
    palette.setColor(QPalette::LinkVisited, QColor(12, 116, 130));
    palette.setColor(QPalette::Highlight, QColor(42, 197, 218));
    palette.setColor(QPalette::Disabled, QPalette::Highlight, QColor(80, 80, 80));
    palette.setColor(QPalette::HighlightedText, Qt::white);
    palette.setColor(QPalette::Disabled, QPalette::HighlightedText, QColor(127, 127, 127));
    return palette;
}

int main(int argc, char* argv[])
{
    QApplication::setApplicationName(Constants::appName);
    QApplication::setApplicationVersion(Constants::appVersion);
    QApplication::setApplicationDisplayName("L8W8JWT GUI");
    QApplication::setOrganizationName(Constants::orgName);
    QApplication::setOrganizationDomain(Constants::orgDomain);

    QApplication application(argc, argv);
    application.setWindowIcon(QIcon(":/img/icon.png"));
    application.setStyle(QStyleFactory::create("Fusion"));
    application.setPalette(getDarkFusionPalette());

    QFile theme(QCoreApplication::applicationDirPath() + "/theme.qss");
    if (theme.exists())
    {
        theme.open(QFile::ReadOnly);
        application.setStyleSheet(QLatin1String(theme.readAll()));
    }

    MainWindow window;

    QObject::connect(&application, SIGNAL(focusChanged(QWidget*,QWidget*)), &window, SLOT(onChangedFocus(QWidget*,QWidget*)));

    window.show();

    return application.exec();
}
