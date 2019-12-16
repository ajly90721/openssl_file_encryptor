#pragma once
#pragma warning(once:4996) 
#include <fstream>    
#include <iostream>    
#include "openssl/des.h"    
#include "EncryptorRSA.h"
using namespace std;
class EncryptorDES
{
public:
	void Encrypt();
	void Decrypt();
	void Encrypt_hybrid();
	void Decrypt_hybrid();
	void Encrypt_hybrid_sign();
	void Decrypt_hybrid_verify();
public:
	EncryptorRSA er;

};

