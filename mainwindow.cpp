#include "mainwindow.h"
#include "ui_mainwindow.h"



MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->btnCryptFile, SIGNAL(clicked()), this, SLOT(cryptFile()));
    connect(ui->btnDecryptFile, SIGNAL(clicked()), this, SLOT(decryptFile()));

    key[0] = 1;
    key[1] = 2;
    key[2] = 3;
    key[3] = 4;
    key[4] = 5;
    key[5] = 6;
    key[6] = 7;
    key[7] = 8;
    des.generate_keys(key);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void
MainWindow::cryptFile() {
    QString fileName = QFileDialog::getOpenFileName(nullptr,"Open Dialog");
    std::cout << fileName.toStdString() << std::endl;

    clock_t begin = clock();
    // FILE
    std::vector<unsigned char> buffer;
    long length;
    if(FILE *freader = fopen(fileName.toStdString().c_str(), "rb")){
        fseek(freader, 0, SEEK_END);
        length = ftell(freader);
        fseek(freader, 0, SEEK_SET);

        if (length > 0) {
            buffer.resize(length);
            fread(&buffer[0], length, 1, freader);
        }
        fclose(freader);
    } else {
        return;
    }

//    des.print_bits_to_line(buffer.data(), length, "open in file");
    uint8_t * output;
    int32_t add_bits = 0;
    int32_t len = des.start(buffer.data(), length, &output, add_bits);
//    des.print_bits_to_line(output, len, "in file");

    FILE *fwriter = fopen((fileName + outFileSuffix).toStdString().c_str(), "wb");
    fwrite(&add_bits, sizeof(add_bits), 1, fwriter);
    fwrite(output, len, 1, fwriter);
    fclose(fwriter);

    delete [] output;

    std::cout << clock() - begin << std::endl;
}

void
MainWindow::decryptFile() {
    QString fileName = QFileDialog::getOpenFileName(nullptr, "Open Dialog");
    std::cout << fileName.toStdString() << std::endl;

    clock_t begin = clock();

    int32_t add_bits = 0;
    // FILE
    std::vector<unsigned char> buffer;
    long length;
    if(FILE *freader = fopen(fileName.toStdString().c_str(), "rb")){
        fread(&add_bits, sizeof(add_bits), 1, freader);

        fseek(freader, 0, SEEK_END);
        length = ftell(freader) - sizeof(add_bits);
        fseek(freader, sizeof(add_bits), SEEK_SET);

        if (length > 0) {
            buffer.resize(length);
            fread(&buffer[0], length, 1, freader);
        }
        fclose(freader);
    } else {
        return;
    }

    uint8_t * output;
    int32_t len = des.startDecrypt(buffer.data(), length, &output, add_bits);

    int dotPos = fileName.lastIndexOf(QChar('.'));
    FILE *fwriter = fopen((fileName.left(dotPos) + "new").toStdString().c_str(), "wb");
    fwrite(output, len, 1, fwriter);
    fclose(fwriter);

    delete [] output;

    std::cout << clock() - begin << std::endl;
}


