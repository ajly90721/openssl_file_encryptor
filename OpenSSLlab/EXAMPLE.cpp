////#include <iostream>    
////#include <cassert>  
////#include <string>    
////#include <vector>    
////#include "openssl/md5.h"    
////#include "openssl/sha.h"    
////#include "openssl/des.h"    
////#include "openssl/rsa.h"    
////#include "openssl/pem.h"    
////using namespace std;
////
////// ---- md5ժҪ��ϣ ---- //    
////void md5(const std::string& srcStr, std::string& encodedStr, std::string& encodedHexStr)
////{
////    // ����md5��ϣ    
////    unsigned char mdStr[33] = { 0 };
////    MD5((const unsigned char*)srcStr.c_str(), srcStr.length(), mdStr);
////
////    // ��ϣ����ַ���    
////    encodedStr = std::string((const char*)mdStr);
////    // ��ϣ���ʮ�����ƴ� 32�ֽ�    
////    char buf[65] = { 0 };
////    char tmp[3] = { 0 };
////    for (int i = 0; i < 32; i++)
////    {
////        sprintf_s(tmp, "%02x", mdStr[i]);
////        strcat_s(buf, tmp);
////    }
////    buf[32] = '\0'; // ���涼��0����32�ֽڽض�    
////    encodedHexStr = std::string(buf);
////}
////
////// ---- sha256ժҪ��ϣ ---- //    
////void sha256(const std::string& srcStr, std::string& encodedStr, std::string& encodedHexStr)
////{
////    // ����sha256��ϣ    
////    unsigned char mdStr[33] = { 0 };
////    SHA256((const unsigned char*)srcStr.c_str(), srcStr.length(), mdStr);
////
////    // ��ϣ����ַ���    
////    encodedStr = std::string((const char*)mdStr);
////    // ��ϣ���ʮ�����ƴ� 32�ֽ�    
////    char buf[65] = { 0 };
////    char tmp[3] = { 0 };
////    for (int i = 0; i < 32; i++)
////    {
////        sprintf_s(tmp, "%02x", mdStr[i]);
////        strcat_s(buf, tmp);
////    }
////    buf[32] = '\0'; // ���涼��0����32�ֽڽض�    
////    encodedHexStr = std::string(buf);
////}
////
////// ---- des�ԳƼӽ��� ---- //    
////// ���� ecbģʽ    
////std::string des_encrypt(const std::string& clearText, const std::string& key)
////{
////    std::string cipherText; // ����    
////
////    DES_cblock keyEncrypt;
////    memset(keyEncrypt, 0, 8);
////
////    // ���첹������Կ    
////    if (key.length() <= 8)
////        memcpy(keyEncrypt, key.c_str(), key.length());
////    else
////        memcpy(keyEncrypt, key.c_str(), 8);
////
////    // ��Կ�û�    
////    DES_key_schedule keySchedule;
////    DES_set_key_unchecked(&keyEncrypt, &keySchedule);
////
////    // ѭ�����ܣ�ÿ8�ֽ�һ��    
////    const_DES_cblock inputText;
////    DES_cblock outputText;
////    std::vector<unsigned char> vecCiphertext;
////    unsigned char tmp[8];
////
////    for (int i = 0; i < clearText.length() / 8; i++)
////    {
////        memcpy(inputText, clearText.c_str() + i * 8, 8);
////        DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
////        memcpy(tmp, outputText, 8);
////
////        for (int j = 0; j < 8; j++)
////            vecCiphertext.push_back(tmp[j]);
////    }
////
////    if (clearText.length() % 8 != 0)
////    {
////        int tmp1 = clearText.length() / 8 * 8;
////        int tmp2 = clearText.length() - tmp1;
////        memset(inputText, 0, 8);
////        memcpy(inputText, clearText.c_str() + tmp1, tmp2);
////        // ���ܺ���    
////        DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_ENCRYPT);
////        memcpy(tmp, outputText, 8);
////
////        for (int j = 0; j < 8; j++)
////            vecCiphertext.push_back(tmp[j]);
////    }
////
////    cipherText.clear();
////    cipherText.assign(vecCiphertext.begin(), vecCiphertext.end());
////
////    return cipherText;
////}
////
////// ���� ecbģʽ    
////std::string des_decrypt(const std::string& cipherText, const std::string& key)
////{
////    std::string clearText; // ����    
////
////    DES_cblock keyEncrypt;
////    memset(keyEncrypt, 0, 8);
////
////    if (key.length() <= 8)
////        memcpy(keyEncrypt, key.c_str(), key.length());
////    else
////        memcpy(keyEncrypt, key.c_str(), 8);
////
////    DES_key_schedule keySchedule;
////		DES_set_key_unchecked(&keyEncrypt, &keySchedule);
////
////		const_DES_cblock inputText;
////		DES_cblock outputText;
////		std::vector<unsigned char> vecCleartext;
////		unsigned char tmp[8];
////
////
////    for (int i = 0; i < cipherText.length() / 8; i++)
////    {
////        memcpy(inputText, cipherText.c_str() + i * 8, 8);
////        DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);
////        memcpy(tmp, outputText, 8);
////
////        for (int j = 0; j < 8; j++)
////            vecCleartext.push_back(tmp[j]);
////    }
////
////    if (cipherText.length() % 8 != 0)
////    {
////        int tmp1 = cipherText.length() / 8 * 8;
////        int tmp2 = cipherText.length() - tmp1;
////        memset(inputText, 0, 8);
////        memcpy(inputText, cipherText.c_str() + tmp1, tmp2);
////        // ���ܺ���    
////        DES_ecb_encrypt(&inputText, &outputText, &keySchedule, DES_DECRYPT);
////        memcpy(tmp, outputText, 8);
////
////        for (int j = 0; j < 8; j++)
////            vecCleartext.push_back(tmp[j]);
////    }
////
////    clearText.clear();
////    clearText.assign(vecCleartext.begin(), vecCleartext.end());
////
////    return clearText;
////}
////
////
////// ---- rsa�ǶԳƼӽ��� ---- //    
////#define KEY_LENGTH  2048               // ��Կ����  
////#define PUB_KEY_FILE "pubkey.pem"    // ��Կ·��  
////#define PRI_KEY_FILE "prikey.pem"    // ˽Կ·��  
////
////// ��������������Կ��   
////void generateRSAKey(std::string strKey[2])
////{
////    // ��˽��Կ��    
////    size_t pri_len;
////    size_t pub_len;
////    char* pri_key = NULL;
////    char* pub_key = NULL;
////
////    // ������Կ��    
////    RSA* keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);
////
////    BIO* pri = BIO_new(BIO_s_mem());
////    BIO* pub = BIO_new(BIO_s_mem());
////
////    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
////    PEM_write_bio_RSAPublicKey(pub, keypair);
////
////    // ��ȡ����    
////    pri_len = BIO_pending(pri);
////    pub_len = BIO_pending(pub);
////
////    // ��Կ�Զ�ȡ���ַ���    
////    pri_key = (char*)malloc(pri_len + 1);
////    pub_key = (char*)malloc(pub_len + 1);
////
////    BIO_read(pri, pri_key, pri_len);
////    BIO_read(pub, pub_key, pub_len);
////
////    pri_key[pri_len] = '\0';
////    pub_key[pub_len] = '\0';
////
////    // �洢��Կ��    
////    strKey[0] = pub_key;
////    strKey[1] = pri_key;
////
////    // �洢�����̣����ַ�ʽ�洢����begin rsa public key/ begin rsa private key��ͷ�ģ� 
////    FILE* pubFile=NULL;//����һ���ļ�����ָ��
////    errno_t err;        //�жϴ��ļ����Ƿ���� ���ڷ���1
////    err = fopen_s(&pubFile, PUB_KEY_FILE, "w"); //�򿪳ɹ��Ļ�err=0�������0
////
////    if (err!=0)
////    {
////        assert(false);
////        return;
////    }
////    fputs(pub_key, pubFile);
////    fclose(pubFile);
////
////    FILE* priFile = NULL;//����һ���ļ�����ָ��
////    err = fopen_s(&priFile, PRI_KEY_FILE, "w"); //�򿪳ɹ��Ļ�err=0�������0
////
////    if (err != 0)
////    {
////        assert(false);
////        return;
////    }
////    fputs(pri_key, priFile);
////    fclose(priFile);
////
////    // �ڴ��ͷ�  
////    RSA_free(keypair);
////    BIO_free_all(pub);
////    BIO_free_all(pri);
////
////    free(pri_key);
////    free(pub_key);
////}
////
////// �����з������ɹ�˽Կ�ԣ�begin public key/ begin private key��  
////// �ҵ�openssl�����й��ߣ���������  
//////genrsa -out prikey.pem 1024   
////// rsa -in prikey.pem -pubout -out pubkey.pem 
////
////// ��Կ����    
////std::string rsa_pub_encrypt(const std::string& clearText, const std::string& pubKey)
////{
////    std::string strRet;
////    RSA* rsa = NULL;
////    BIO* keybio = BIO_new_mem_buf((unsigned char*)pubKey.c_str(), -1);
////    // �˴������ַ���  
////    // 1, ��ȡ�ڴ������ɵ���Կ�ԣ��ٴ��ڴ�����rsa  
////    // 2, ��ȡ���������ɵ���Կ���ı��ļ����ڴ��ڴ�����rsa  
////    // 3��ֱ�ӴӶ�ȡ�ļ�ָ������rsa  
////    RSA* pRSAPublicKey = RSA_new();
////    rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
////
////    int len = RSA_size(rsa);
////    char* encryptedText = (char*)malloc(len + 1);
////    memset(encryptedText, 0, len + 1);
////
////    // ���ܺ���  
////    int ret = RSA_public_encrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);
////    if (ret >= 0)
////        strRet = std::string(encryptedText, ret);
////
////    // �ͷ��ڴ�  
////    free(encryptedText);
////    BIO_free_all(keybio);
////    RSA_free(rsa);
////
////    return strRet;
////}
////
////// ˽Կ����    
////std::string rsa_pri_decrypt(const std::string& cipherText, const std::string& priKey)
////{
////    std::string strRet;
////    RSA* rsa = RSA_new();
////    BIO* keybio;
////    keybio = BIO_new_mem_buf((unsigned char*)priKey.c_str(), -1);
////
////    // �˴������ַ���  
////    // 1, ��ȡ�ڴ������ɵ���Կ�ԣ��ٴ��ڴ�����rsa  
////    // 2, ��ȡ���������ɵ���Կ���ı��ļ����ڴ��ڴ�����rsa  
////    // 3��ֱ�ӴӶ�ȡ�ļ�ָ������rsa  
////    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
////
////    int len = RSA_size(rsa);
////    char* decryptedText = (char*)malloc(len + 1);
////    memset(decryptedText, 0, len + 1);
////
////    // ���ܺ���  
////    int ret = RSA_private_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, rsa, RSA_PKCS1_PADDING);
////    if (ret >= 0)
////        strRet = std::string(decryptedText, ret);
////
////    // �ͷ��ڴ�  
////    free(decryptedText);
////    BIO_free_all(keybio);
////    RSA_free(rsa);
////
////    return strRet;
////}
////
////int main(int argc, char** argv)
////{
//////     ԭʼ����    
////    std::string srcText = "this is an example";
////
////    std::string encryptText;
////    std::string encryptHexText;
////    std::string decryptText;
////
////    std::cout << "=== ԭʼ���� ===" << std::endl;
////    std::cout << srcText << std::endl;
//////
//////     md5    
////    std::cout << "=== md5��ϣ ===" << std::endl;
////    md5(srcText, encryptText, encryptHexText);
////    std::cout << "ժҪ�ַ��� " << encryptText << std::endl;
////    std::cout << "ժҪ���� " << encryptHexText << std::endl;
//////
//////     sha256    
////    std::cout << "=== sha256��ϣ ===" << std::endl;
////    sha256(srcText, encryptText, encryptHexText);
////    std::cout << "ժҪ�ַ��� " << encryptText << std::endl;
////    std::cout << "ժҪ���� " << encryptHexText << std::endl;
//////
//////     des    
////    std::cout << "=== des�ӽ��� ===" << std::endl;
////    std::string desKey = "12345";
////    encryptText = des_encrypt(srcText, desKey);
////    std::cout << "�����ַ��� " << std::endl;
////    std::cout << encryptText << std::endl;
////    decryptText = des_decrypt(encryptText, desKey);
////    std::cout << "�����ַ��� " << std::endl;
////    std::cout << decryptText << std::endl;
//////
//////     rsa    
////    std::cout << "=== rsa�ӽ��� ===" << std::endl;
////    std::string key[2];
////    generateRSAKey(key);
////    std::cout << "��Կ: " << std::endl;
////    std::cout << key[0] << std::endl;
////    std::cout << "˽Կ�� " << std::endl;
////    std::cout << key[1] << std::endl;
////    encryptText = rsa_pub_encrypt(srcText, key[0]);
////    std::cout << "�����ַ��� " << std::endl;
////    std::cout << encryptText << std::endl;
////    decryptText = rsa_pri_decrypt(encryptText, key[1]);
////    std::cout << "�����ַ��� " << std::endl;
////    std::cout << decryptText << std::endl;
////
////    system("pause");
////    return 0;
////}
//
//#include <iostream>
//#include <openssl/aes.h>
//#include <openssl/evp.h>
//#include <openssl/rsa.h>
//#include <openssl/pem.h>
//#include <openssl/ssl.h>
//#include <openssl/bio.h>
//#include <openssl/err.h>
//#include <assert.h>
//
//std::string privateKey = "-----BEGIN RSA PRIVATE KEY-----\n"\
//"MIIEowIBAAKCAQEAy8Dbv8prpJ/0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy\n"\
//"vGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+vw1HocOAZtWK0z3r26uA8kQYOKX9\n"\
//"Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQApfc9jB9nTzphOgM4JiEYvlV8FLhg9\n"\
//"yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68i6T4nNq7NWC+UNVjQHxNQMQMzU6l\n"\
//"WCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoVPpY72+eVthKzpMeyHkBn7ciumk5q\n"\
//"gLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUywQIDAQABAoIBADhg1u1Mv1hAAlX8\n"\
//"omz1Gn2f4AAW2aos2cM5UDCNw1SYmj+9SRIkaxjRsE/C4o9sw1oxrg1/z6kajV0e\n"\
//"N/t008FdlVKHXAIYWF93JMoVvIpMmT8jft6AN/y3NMpivgt2inmmEJZYNioFJKZG\n"\
//"X+/vKYvsVISZm2fw8NfnKvAQK55yu+GRWBZGOeS9K+LbYvOwcrjKhHz66m4bedKd\n"\
//"gVAix6NE5iwmjNXktSQlJMCjbtdNXg/xo1/G4kG2p/MO1HLcKfe1N5FgBiXj3Qjl\n"\
//"vgvjJZkh1as2KTgaPOBqZaP03738VnYg23ISyvfT/teArVGtxrmFP7939EvJFKpF\n"\
//"1wTxuDkCgYEA7t0DR37zt+dEJy+5vm7zSmN97VenwQJFWMiulkHGa0yU3lLasxxu\n"\
//"m0oUtndIjenIvSx6t3Y+agK2F3EPbb0AZ5wZ1p1IXs4vktgeQwSSBdqcM8LZFDvZ\n"\
//"uPboQnJoRdIkd62XnP5ekIEIBAfOp8v2wFpSfE7nNH2u4CpAXNSF9HsCgYEA2l8D\n"\
//"JrDE5m9Kkn+J4l+AdGfeBL1igPF3DnuPoV67BpgiaAgI4h25UJzXiDKKoa706S0D\n"\
//"4XB74zOLX11MaGPMIdhlG+SgeQfNoC5lE4ZWXNyESJH1SVgRGT9nBC2vtL6bxCVV\n"\
//"WBkTeC5D6c/QXcai6yw6OYyNNdp0uznKURe1xvMCgYBVYYcEjWqMuAvyferFGV+5\n"\
//"nWqr5gM+yJMFM2bEqupD/HHSLoeiMm2O8KIKvwSeRYzNohKTdZ7FwgZYxr8fGMoG\n"\
//"PxQ1VK9DxCvZL4tRpVaU5Rmknud9hg9DQG6xIbgIDR+f79sb8QjYWmcFGc1SyWOA\n"\
//"SkjlykZ2yt4xnqi3BfiD9QKBgGqLgRYXmXp1QoVIBRaWUi55nzHg1XbkWZqPXvz1\n"\
//"I3uMLv1jLjJlHk3euKqTPmC05HoApKwSHeA0/gOBmg404xyAYJTDcCidTg6hlF96\n"\
//"ZBja3xApZuxqM62F6dV4FQqzFX0WWhWp5n301N33r0qR6FumMKJzmVJ1TA8tmzEF\n"\
//"yINRAoGBAJqioYs8rK6eXzA8ywYLjqTLu/yQSLBn/4ta36K8DyCoLNlNxSuox+A5\n"\
//"w6z2vEfRVQDq4Hm4vBzjdi3QfYLNkTiTqLcvgWZ+eX44ogXtdTDO7c+GeMKWz4XX\n"\
//"uJSUVL5+CVjKLjZEJ6Qc2WZLl94xSwL71E41H4YciVnSCQxVc4Jw\n"\
//"-----END RSA PRIVATE KEY-----\n\0";
//
//std::string publicKey = "-----BEGIN PUBLIC KEY-----\n"\
//"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ/0kKhlGeJY\n"\
//"ozo2t60EG8L0561g13R29LvMR5hyvGZlGJpmn65+A4xHXInJYiPuKzrKUnApeLZ+\n"\
//"vw1HocOAZtWK0z3r26uA8kQYOKX9Qt/DbCdvsF9wF8gRK0ptx9M6R13NvBxvVQAp\n"\
//"fc9jB9nTzphOgM4JiEYvlV8FLhg9yZovMYd6Wwf3aoXK891VQxTr/kQYoq1Yp+68\n"\
//"i6T4nNq7NWC+UNVjQHxNQMQMzU6lWCX8zyg3yH88OAQkUXIXKfQ+NkvYQ1cxaMoV\n"\
//"PpY72+eVthKzpMeyHkBn7ciumk5qgLTEJAfWZpe4f4eFZj/Rc8Y8Jj2IS5kVPjUy\n"\
//"wQIDAQAB\n"\
//"-----END PUBLIC KEY-----\n";
//
//RSA* createPrivateRSA(std::string key) {
//    RSA* rsa = NULL;
//    const char* c_string = key.c_str();
//    BIO* keybio = BIO_new_mem_buf((void*)c_string, -1);
//    if (keybio == NULL) {
//        return 0;
//    }
//    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
//    return rsa;
//}
//
//RSA* createPublicRSA(std::string key) {
//    RSA* rsa = NULL;
//    BIO* keybio;
//    const char* c_string = key.c_str();
//    keybio = BIO_new_mem_buf((void*)c_string, -1);
//    if (keybio == NULL) {
//        return 0;
//    }
//    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
//    return rsa;
//}
//
//bool RSASign(RSA* rsa,
//    const unsigned char* Msg,
//    size_t MsgLen,
//    unsigned char** EncMsg,
//    size_t* MsgLenEnc) {
//    EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
//    EVP_PKEY* priKey = EVP_PKEY_new();
//    EVP_PKEY_assign_RSA(priKey, rsa);
//    if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0) {
//        return false;
//    }
//    if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
//        return false;
//    }
//    if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <= 0) {
//        return false;
//    }
//    *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
//    if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
//        return false;
//    }
//    //EVP_MD_CTX_cleanup(m_RSASignCtx);
//    return true;
//}
//
//bool RSAVerifySignature(RSA* rsa,
//    unsigned char* MsgHash,
//    size_t MsgHashLen,
//    const char* Msg,
//    size_t MsgLen,
//    bool* Authentic) {
//    *Authentic = false;
//    EVP_PKEY* pubKey = EVP_PKEY_new();
//    EVP_PKEY_assign_RSA(pubKey, rsa);
//    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();
//
//    if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0) {
//        return false;
//    }
//    if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
//        return false;
//    }
//    int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
//    if (AuthStatus == 1) {
//        *Authentic = true;
//        //EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
//        return true;
//    }
//    else if (AuthStatus == 0) {
//        *Authentic = false;
//        //EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
//        return true;
//    }
//    else {
//        *Authentic = false;
//        //EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
//        return false;
//    }
//}
//
//void Base64Encode(const unsigned char* buffer,
//    size_t length,
//    char** base64Text) {
//    BIO* bio, * b64;
//    BUF_MEM* bufferPtr;
//
//    b64 = BIO_new(BIO_f_base64());
//    bio = BIO_new(BIO_s_mem());
//    bio = BIO_push(b64, bio);
//
//    BIO_write(bio, buffer, length);
//    BIO_flush(bio);
//    BIO_get_mem_ptr(bio, &bufferPtr);
//    BIO_set_close(bio, BIO_NOCLOSE);
//    BIO_free_all(bio);
//
//    *base64Text = (*bufferPtr).data;
//}
//
//size_t calcDecodeLength(const char* b64input) {
//    size_t len = strlen(b64input), padding = 0;
//
//    if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are =
//        padding = 2;
//    else if (b64input[len - 1] == '=') //last char is =
//        padding = 1;
//    return (len * 3) / 4 - padding;
//}
//
//void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
//    BIO* bio, * b64;
//
//    int decodeLen = calcDecodeLength(b64message);
//    *buffer = (unsigned char*)malloc(decodeLen + 1);
//    (*buffer)[decodeLen] = '\0';
//
//    bio = BIO_new_mem_buf(b64message, -1);
//    b64 = BIO_new(BIO_f_base64());
//    bio = BIO_push(b64, bio);
//
//    *length = BIO_read(bio, *buffer, strlen(b64message));
//    BIO_free_all(bio);
//}
//
//char* signMessage(std::string privateKey, std::string plainText) {
//    RSA* privateRSA = createPrivateRSA(privateKey);
//    unsigned char* encMessage;
//    char* base64Text;
//    size_t encMessageLength;
//    RSASign(privateRSA, (unsigned char*)plainText.c_str(), plainText.length(), &encMessage, &encMessageLength);
//    Base64Encode(encMessage, encMessageLength, &base64Text);
//    free(encMessage);
//    return base64Text;
//}
//
//bool verifySignature(std::string publicKey, std::string plainText, char* signatureBase64) {
//    RSA* publicRSA = createPublicRSA(publicKey);
//    unsigned char* encMessage;
//    size_t encMessageLength;
//    bool authentic;
//    Base64Decode(signatureBase64, &encMessage, &encMessageLength);
//    bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText.c_str(), plainText.length(), &authentic);
//    return result & authentic;
//}
//
//int main() {
//    std::string plainText = "My secret message.\n";
//    char* signature = signMessage(privateKey, plainText);
//    bool authentic = verifySignature(publicKey, "My secret message.\n", signature);
//    if (authentic) {
//        std::cout << "Authentic" << std::endl;
//    }
//    else {
//        std::cout << "Not Authentic" << std::endl;
//    }
//}