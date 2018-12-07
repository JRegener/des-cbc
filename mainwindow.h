#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "descrypt.h"

#include <iostream>
#include <time.h>
#include <QFileDialog>
#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Ui::MainWindow *ui;

    unsigned char key[8];
    const char outFileSuffix[7] = ".crypt";
    DESCrypt des = DESCrypt();

private slots:
    void cryptFile();
    void decryptFile();
};

#endif // MAINWINDOW_H
