#include "EncryptorRSA.h"
#include <cassert> 
#include <fstream>
RSA* EncryptorRSA::createPrivateRSA(std::string key) {
    RSA* rsa = NULL;
    const char* c_string = key.c_str();
    BIO* keybio = BIO_new_mem_buf((void*)c_string, -1);
    if (keybio == NULL) {
        return 0;
    }
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    return rsa;
}

RSA* EncryptorRSA::createPublicRSA(std::string key) {
    RSA* rsa = NULL;
    BIO* keybio;
    const char* c_string = key.c_str();
    keybio = BIO_new_mem_buf((void*)c_string, -1);
    if (keybio == NULL) {
        return 0;
    }
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    return rsa;
}
string EncryptorRSA::Encrypt_public(string& clearText)
{
    string pubKey = getKeyLocal("pubKey");

    std::string strRet;
    RSA* rsa = createPublicRSA(pubKey);

    int len = RSA_size(rsa);
    char* encryptedText = (char*)malloc(len + 1);
    memset(encryptedText, 0, len + 1);

    // 加密函数  
    int ret = RSA_public_encrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0)
        strRet = std::string(encryptedText, ret);

    // 释放内存  
    free(encryptedText);
    RSA_free(rsa);

    return strRet;
}
string EncryptorRSA::Decrypt_private(string& cipherText)
{
    string priKey = getKeyLocal("priKey");

    RSA* rsa = createPrivateRSA(priKey);

    string strRet="";
    int len = RSA_size(rsa);
    char* decryptedText = (char*)malloc(len + 1);
    memset(decryptedText, 0, len + 1);

    // 解密函数  
    int ret = RSA_private_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, rsa, RSA_PKCS1_PADDING);
    if (ret >= 0)
        strRet = std::string(decryptedText, ret);

    // 释放内存  
    free(decryptedText);
    RSA_free(rsa);

    return strRet;
}

string EncryptorRSA::getKeyLocal(string type)
{
    string key = "";
    string path;
    fstream fs;
    if (type == "priKey")
    {
        cout << "enter your private key path" << endl;
        cin >> path;

        fs.open(path);
        if (!fs)
        {
            cout << "open prikey error \n";
            return "open prikey error";
        }
        char c;
        fs >> noskipws;
        while (!fs.eof())
        {
            fs >> c;
            key = key + c;
        }
        cout << "prikey:\n" << key;
    }
    if (type == "pubKey")
    {
        cout << "enter your public key path" << endl;
        cin >> path;
        fs.open(path);
        if (!fs)
        {
            cout << "open pubkey error \n";
            return "open pubkey error";
        }
        char c;
        fs >> noskipws;
        while (!fs.eof())
        {
            fs >> c;
            key = key + c;
        }
        cout << "pubkey length is" << key.length() << endl;
        cout << "pubkey:\n" << key.c_str();
        fs.close();
    }
    fs.close();
    return key;
}


bool EncryptorRSA::RSASign(RSA* rsa,
    const unsigned char* Msg,
    size_t MsgLen,
    unsigned char** EncMsg,
    size_t* MsgLenEnc) {
    EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
    EVP_PKEY* priKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priKey, rsa);
    if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0) {
        return false;
    }
    if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
        return false;
    }
    if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <= 0) {
        return false;
    }
    *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
    if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
        return false;
    }
    EVP_MD_CTX_free(m_RSASignCtx);
    return true;
}

bool EncryptorRSA::RSAVerifySignature(RSA* rsa,
    unsigned char* MsgHash,
    size_t MsgHashLen,
    const char* Msg,
    size_t MsgLen,
    bool* Authentic) {
    *Authentic = false;
    EVP_PKEY* pubKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, rsa);
    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

    if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0) {
        return false;
    }
    if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
        return false;
    }
    int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
    if (AuthStatus == 1) {
        *Authentic = true;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return true;
    }
    else if (AuthStatus == 0) {
        *Authentic = false;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return true;
    }
    else {
        *Authentic = false;
        EVP_MD_CTX_free(m_RSAVerifyCtx);
        return false;
    }
}

void EncryptorRSA::Base64Encode(const unsigned char* buffer,
    size_t length,
    char** base64Text) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *base64Text = (*bufferPtr).data;
}

size_t EncryptorRSA::calcDecodeLength(const char* b64input) {
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len - 1] == '=') //last char is =
        padding = 1;
    return (len * 3) / 4 - padding;
}

void EncryptorRSA::Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
    BIO* bio, * b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
}

char* EncryptorRSA::signMessage(std::string privateKey, std::string plainText) {
    RSA* privateRSA = createPrivateRSA(privateKey);
    unsigned char* encMessage;
    char* base64Text;
    size_t encMessageLength;

    RSASign(privateRSA, (unsigned char*)plainText.c_str(), plainText.length(), &encMessage, &encMessageLength);
    Base64Encode(encMessage, encMessageLength, &base64Text);
    free(encMessage);
    return base64Text;
}
bool EncryptorRSA::verifySignature(std::string publicKey, std::string plainText, char* signatureBase64) {
    RSA* publicRSA = createPublicRSA(publicKey);
    unsigned char* encMessage;
    size_t encMessageLength;
    bool authentic;

    Base64Decode(signatureBase64, &encMessage, &encMessageLength);
    bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, plainText.c_str(), plainText.length(), &authentic);
    return result & authentic;
}