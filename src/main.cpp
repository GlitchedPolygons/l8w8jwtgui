#include "mainwindow.h"
#include "constants.h"

#include <QApplication>
#include <QFile>

int main(int argc, char* argv[])
{
    QApplication::setApplicationName(Constants::appName);
    QApplication::setApplicationVersion(Constants::appVersion);
    QApplication::setApplicationDisplayName("L8W8JWT GUI");
    QApplication::setOrganizationName(Constants::orgName);
    QApplication::setOrganizationDomain(Constants::orgDomain);

    QApplication application(argc, argv);
    application.setWindowIcon(QIcon(":/img/icon.png"));

    QFile theme(QCoreApplication::applicationDirPath() + "/theme.qss");
    if (theme.exists())
    {
        theme.open(QFile::ReadOnly);
        application.setStyleSheet(QLatin1String(theme.readAll()));
    }

    MainWindow window;
    window.show();

    return application.exec();
}
