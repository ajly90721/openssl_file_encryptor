#include "EncryptorDES.h"

#include    <vector>
#include    <fstream>
void EncryptorDES::Encrypt()
{
    cout << "====================================DES加密==================================" << endl;
    string key,path;
    //unsigned char in[1024*15];
    cout << "enter the file name" << endl;
    cin >> path;
    cout << "enter the key" << endl;
    cin >> key;

    ifstream infile(path,ios::in|ios::binary);
    infile.seekg(0, ios::end);
    int size = infile.tellg();
    infile.seekg(0, ios::beg);

    cout << "file size" << size << endl;
    unsigned char* in = new unsigned char[size]();

    if (!infile)
    {
        cout << "open error \n";
        return;
    }

    infile.read((char*)in, size);
    infile.close();

    static unsigned char cbc_iv[8] = { '0', '1', 'A', 'B', 'a', 'b', '9', '8' };
    DES_cblock keyEncrypt, ivec;
    memset(keyEncrypt, 0, 8);

    if (key.length() <= 8)
        memcpy(keyEncrypt, key.c_str(), key.length());
    else
        memcpy(keyEncrypt, key.c_str(), 8);

    DES_key_schedule keySchedule;  //密钥表
    DES_set_key_unchecked(&keyEncrypt, &keySchedule);   //设置密钥，且不检测密钥奇偶性  

    memcpy(ivec, cbc_iv, sizeof(cbc_iv));

    int iLength = size % 8 ? (size / 8 + 1) * 8 : size;
    unsigned char* tmp = new unsigned char[iLength + 16];
    memset(tmp, 0, iLength);

    DES_ncbc_encrypt(in, tmp, size, &keySchedule, &ivec, DES_ENCRYPT);  //加密

    ofstream outfile("b",ios::out|ios::binary);
    outfile << size;
    outfile.write((const char*)tmp, iLength);
    //把加密后的密文写入新文件
    outfile.close();
    delete[] tmp;
    delete[] in;

    cout << "=========================================DES加密完成===================================" << endl;
}

void EncryptorDES::Decrypt()
{
    cout << "=============================DES解密===================================" << endl;
    string key, path;
 //   unsigned char in[1024 * 15];
    cout << "enter the file name" << endl;
    cin >> path;
    cout << "enter the key" << endl;
    cin >> key;


    ifstream infile(path, ios::in | ios::binary);
    infile.seekg(0, ios::end);
    int size = infile.tellg();
    infile.seekg(0, ios::beg);


    cout << "encrypted file size" << size << endl;

    if (!infile)
    {
        cout << "open error \n";
        return;
    }

    int real_size = 0;
    infile >> real_size;
    cout << "file real size" << real_size << endl;
    size= real_size % 8 ? (real_size / 8 + 1) * 8 : real_size;
    unsigned char* in = new unsigned char[size]();
    infile.read((char*)in, size);
    infile.close();

    static unsigned char cbc_iv[8] = { '0', '1', 'A', 'B', 'a', 'b', '9', '8' };
    DES_cblock keyEncrypt, ivec;
    memset(keyEncrypt, 0, 8);

    if (key.length() <= 8)
        memcpy(keyEncrypt, key.c_str(), key.length());
    else
        memcpy(keyEncrypt, key.c_str(), 8);

    DES_key_schedule keySchedule;  //密钥表
    DES_set_key_unchecked(&keyEncrypt, &keySchedule);   //设置密钥，且不检测密钥奇偶性  

    memcpy(ivec, cbc_iv, sizeof(cbc_iv));

    unsigned char* tmp = new unsigned char[size + 16]();

    DES_ncbc_encrypt(in, tmp, size, &keySchedule, &ivec, DES_DECRYPT);  //加密

    ofstream outfile("b", ios::out | ios::binary);
    outfile.write((const char*)tmp, real_size);
    outfile.close();
    delete[] tmp;
    delete[] in;
    cout << "=========================================DES解密完成===================================" << endl;
}

void EncryptorDES::Encrypt_hybrid()
{
    cout << "=========================================混合加密===================================" << endl;
    string path;
    //unsigned char in[1024 * 13];
    cout << "enter the file name" << endl;
    cin >> path;

    ifstream infile(path, ios::in | ios::binary);
    infile.seekg(0, ios::end);
    int size = infile.tellg();
    infile.seekg(0, ios::beg);
    cout << "file size" << size << endl;
    unsigned char* in = new unsigned char[size]();
    if (!infile)
    {
        cout << "open error \n";
        return;
    }
    infile.read((char*)in, size);
    infile.close();

    static unsigned char cbc_iv[8] = { '0', '1', 'A', 'B', 'a', 'b', '9', '8' };
    DES_cblock keyEncrypt, ivec;
    memset(keyEncrypt, 0, 8);

    DES_random_key(&keyEncrypt);

    DES_key_schedule keySchedule;  //密钥表
    DES_set_key_unchecked(&keyEncrypt, &keySchedule);   //设置密钥，且不检测密钥奇偶性  

    memcpy(ivec, cbc_iv, sizeof(cbc_iv));

    int iLength = size % 8 ? (size / 8 + 1) * 8 : size;
    unsigned char* tmp = new unsigned char[iLength + 16];
    memset(tmp, 0, iLength);

    DES_ncbc_encrypt(in, tmp, size, &keySchedule, &ivec, DES_ENCRYPT);  //加密

    string deskey = (char*)keyEncrypt;
    deskey=er.Encrypt_public(deskey);
    //cout << "deskeylen" << deskey.length()<<endl;

    ofstream outfile("b", ios::out | ios::binary);
    outfile<<deskey.length();
    outfile.write(deskey.c_str(),deskey.length());
    outfile << size;
    outfile.write((const char*)tmp, iLength);
    //把加密后的密文写入新文件
    outfile.close();
    delete[] in;
    delete[] tmp;
    cout << "=========================================混合加密完成===================================" << endl;
}

void EncryptorDES::Decrypt_hybrid()
{
    cout << "=========================================混合解密===================================" << endl;
    string path;

    //unsigned char in[1024 * 13];
    cout << "enter the file name" << endl;
    cin >> path;

    ifstream infile(path, ios::in | ios::binary);
    infile.seekg(0, ios::end);
    int size = infile.tellg();
    infile.seekg(0, ios::beg);
    cout << "file size" << size << endl;
    if (!infile)
    {
        cout << "open error \n";
        return;
    }



    int keylen = 0;
    infile >> keylen;
    cout << "keylen: "<<keylen<<"\n";

    string desKey = "";
    char c;
    infile >> noskipws;
    for(int i=0;i<keylen;i++)
    {
        infile >> c;
        desKey = desKey + c;
    }
    string key=er.Decrypt_private(desKey);

    int real_size;
    infile >> real_size;
    size = real_size % 8 ? (real_size / 8 + 1) * 8 : real_size;
    unsigned char* in = new unsigned char[size]();
    infile.read((char*)in, size);
    infile.close();



    static unsigned char cbc_iv[8] = { '0', '1', 'A', 'B', 'a', 'b', '9', '8' };
    DES_cblock keyEncrypt, ivec;
    memset(keyEncrypt, 0, 8);

    if (key.length() <= 8)
        memcpy(keyEncrypt, key.c_str(), key.length());
    else
        memcpy(keyEncrypt, key.c_str(), 8);

    DES_key_schedule keySchedule;  //密钥表
    DES_set_key_unchecked(&keyEncrypt, &keySchedule);   //设置密钥，且不检测密钥奇偶性  

    memcpy(ivec, cbc_iv, sizeof(cbc_iv));

    unsigned char* tmp = new unsigned char[size + 16]();

    DES_ncbc_encrypt(in, tmp, size, &keySchedule, &ivec, DES_DECRYPT);  //加密

    ofstream outfile("b", ios::out | ios::binary);
    outfile.write((const char*)tmp, real_size);
    outfile.close();
    delete[] tmp;
    delete[] in;
    cout << "=========================================混合解密完成===================================" << endl;
}

void EncryptorDES::Encrypt_hybrid_sign()
{
    cout << "=========================================混合加密带签名===================================" << endl;
    string path;
    //unsigned char in[1024 * 13];
    cout << "enter the file name" << endl;
    cin >> path;

    ifstream infile(path, ios::in | ios::binary);
    infile.seekg(0, ios::end);
    int size = infile.tellg();
    infile.seekg(0, ios::beg);
    cout << "file size" << size << endl;
    unsigned char* in = new unsigned char[size]();
    if (!infile)
    {
        cout << "open error \n";
        return;
    }
    infile.read((char*)in, size);
    infile.close();

    string sign=er.signMessage(er.getKeyLocal("priKey"), (char*)in);

    static unsigned char cbc_iv[8] = { '0', '1', 'A', 'B', 'a', 'b', '9', '8' };
    DES_cblock keyEncrypt, ivec;
    memset(keyEncrypt, 0, 8);

    DES_random_key(&keyEncrypt);

    DES_key_schedule keySchedule;  //密钥表
    DES_set_key_unchecked(&keyEncrypt, &keySchedule);   //设置密钥，且不检测密钥奇偶性  

    memcpy(ivec, cbc_iv, sizeof(cbc_iv));

    int iLength = size % 8 ? (size / 8 + 1) * 8 : size;
    unsigned char* tmp = new unsigned char[iLength + 16];
    memset(tmp, 0, iLength);

    DES_ncbc_encrypt(in, tmp, size, &keySchedule, &ivec, DES_ENCRYPT);  //加密

    string deskey = (char*)keyEncrypt;
    deskey = er.Encrypt_public(deskey);
    //cout << "deskeylen" << deskey.length() << endl;

    ofstream outfile("b", ios::out | ios::binary);
    //新文件构成：签名长度+签名+des密钥长度+des密钥+原本文件长度+加密的文件
    outfile << sign.length();
    outfile.write(sign.c_str(), sign.length());
    outfile << deskey.length();
    outfile.write(deskey.c_str(), deskey.length());
    outfile << size;
    outfile.write((const char*)tmp, iLength);
    //把加密后的密文写入新文件
    outfile.close();
    delete[] in;
    delete[] tmp;
    cout << "=========================================混合加密带签名完成===================================" << endl;
}

void EncryptorDES::Decrypt_hybrid_verify()
{
    cout << "=========================================混合解密带验证===================================" << endl;
    string path;
    //unsigned char in[1024 * 13];
    cout << "enter the file name" << endl;
    cin >> path;

    ifstream infile(path, ios::in | ios::binary);
    infile.seekg(0, ios::end);
    int size = infile.tellg();
    infile.seekg(0, ios::beg);
    cout << "file size" << size << endl;
    if (!infile)
    {
        cout << "open error \n";
        return;
    }


    int signlen = 0;
    infile >> signlen;
    //cout << "signlen: " << signlen << "\n";

    string sign = "";
    char c;
    infile >> noskipws;
    for (int i = 0; i < signlen; i++)
    {
        infile >> c;
        sign = sign + c;
    }


    int keylen = 0;
    infile >> keylen;
    //cout << "keylen: " << keylen << "\n";

    string desKey = "";
    infile >> noskipws;
    for (int i = 0; i < keylen; i++)
    {
        infile >> c;
        desKey = desKey + c;
    }
    string key = er.Decrypt_private(desKey);

    int real_size = 0;
    infile >> real_size;
    cout << "realsize:" << real_size << endl;
    size = real_size % 8 ? (real_size / 8 + 1) * 8 : real_size;
    unsigned char* in = new unsigned char[size]();
    infile.read((char*)in, size);
    infile.close();



    static unsigned char cbc_iv[8] = { '0', '1', 'A', 'B', 'a', 'b', '9', '8' };
    DES_cblock keyEncrypt, ivec;
    memset(keyEncrypt, 0, 8);

    if (key.length() <= 8)
        memcpy(keyEncrypt, key.c_str(), key.length());
    else
        memcpy(keyEncrypt, key.c_str(), 8);

    DES_key_schedule keySchedule;  //密钥表
    DES_set_key_unchecked(&keyEncrypt, &keySchedule);   //设置密钥，且不检测密钥奇偶性  

    memcpy(ivec, cbc_iv, sizeof(cbc_iv));

    unsigned char* tmp = new unsigned char[size + 16];

    DES_ncbc_encrypt(in, tmp, size, &keySchedule, &ivec, DES_DECRYPT);  //加密

   // cout << "测试" << endl;

    for (int i = real_size; i < strlen((const char*)tmp); i++)
        tmp[i]='\0';
    string decryptText = (char*)tmp;

    bool flag = er.verifySignature(er.getKeyLocal("pubKey"),decryptText,(char*)sign.c_str());
    if (flag) {
        std::cout << "Authentic" << std::endl;
    }
    else {
        std::cout << "Not Authentic" << std::endl;
    }

    ofstream outfile("b", ios::out | ios::binary);
    outfile.write((const char*)tmp, real_size);
    outfile.close();
    delete[] tmp;
    delete[] in;
    cout << "=========================================混合解密带验证完成===================================" << endl;
}


