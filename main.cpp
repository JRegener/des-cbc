#include "mainwindow.h"
#include <QApplication>
#include <fstream>

#include "descrypt.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

//    DESCrypt des;
//    des.test();

//    unsigned char output[] = "1234567";
//    std::ofstream outfile ("first.txt", std::ios_base::out | std::ofstream::binary);
//    outfile.write((const char*)(&output),sizeof(output));
//    outfile.close();


//    std::vector<char> buffer;
//    std::ifstream infile("first.txt", std::ios_base::in | std::ios_base::binary);
//    infile.seekg(0, infile.end);
//    size_t length = infile.tellg();
//    infile.seekg(0, infile.beg);

//    //read file
//    if (length > 0) {
//        buffer.resize(length);
//        infile.read((char*)( &buffer[0]), length);
//    }
//    infile.close();

    return a.exec();
}
