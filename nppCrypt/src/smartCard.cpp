#include "smartCard.h"
#include <winscard.h>
#include "cryptheader.h"
#include <cryptopp/osrng.h>
#include "bignum.h"
#include <cryptopp\pwdbased.h>
#include "cryptopp\modes.h"
#include "cryptopp\rijndael.h"
#include <string.h>
#include "cryptopp\hex.h"

#include <iostream>
#include <fstream>


using namespace CryptoPP;


FILE *f;

LONG SmartCard::SmartCard::sendADPDU(byte cla, byte command, byte p1, byte p2, byte * data, size_t dataSize, LPBYTE returnData, LPDWORD rDataLen, SCARDHANDLE *hCard, SCARD_IO_REQUEST *pioSendPci) {
	LONG returnValue; 

	byte apdu[258];
	apdu[0] = cla;
	apdu[1] = command;
	apdu[2] = p1;
	apdu[3] = p2;

	if (dataSize > 0) {
		apdu[4] = (byte)dataSize ;

		for (size_t count = 0; count < dataSize; count++) {
			apdu[count + 5] = data[count];
		}
	}


	DWORD retSize = 300;
	BYTE retAPDU[300];

	for (int i = 0; i < dataSize + 5; i++) {
		fprintf(f, "%02X ", apdu[i]);
	}

	fprintf(f, "\n");


	returnValue = SCardTransmit(*hCard, pioSendPci, apdu, dataSize + 5, NULL, retAPDU, &retSize);

	if (memcmp(retAPDU + (retSize - 2), Constants::successADPU, 2) == 0) {
		memcpy(returnData, retAPDU, retSize - 2);
	//	return 0;
	};


	//For DEBUG only!

	fprintf(f, "\n" );
	fprintf(f, "size of return data is: %lu\n", retSize);

	for (int i = 0; i < retSize; i++) {
		fprintf(f,"%02X ", retAPDU[i]);
	}

	fprintf(f, "\n");
	return returnValue;
}

LONG SmartCard::SmartCard::connectToCard( SCARDHANDLE *hCard, SCARD_IO_REQUEST *pioSendPci) {
	LONG returnValue;

	LPTSTR mszReaders;
	SCARDCONTEXT hContext;
	DWORD dwReaders, dwActiveProtocol, dwRecvLength;

	
	returnValue = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	
	if (returnValue != 0) {
		return returnValue;
	}
	
	dwReaders = SCARD_AUTOALLOCATE;

	returnValue = SCardListReaders(hContext, NULL, (LPTSTR)&mszReaders, &dwReaders);
	if (returnValue != 0) {
		return returnValue;
	}

	returnValue = SCardConnect(hContext, mszReaders, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, hCard, &dwActiveProtocol);

	switch (dwActiveProtocol) {
	case SCARD_PROTOCOL_T0:
		*pioSendPci = *SCARD_PCI_T0;
		break;

	case SCARD_PROTOCOL_T1:
		*pioSendPci = *SCARD_PCI_T1;
		break;
	}

	return returnValue;

}



LONG SmartCard::SmartCard::selectApplet(SCARDHANDLE *hCard, SCARD_IO_REQUEST *pioSendPci) {
	
	LONG returnValue;

	returnValue = connectToCard(hCard, pioSendPci);
	if (returnValue != 0) {
		return 1;
	}

	BYTE ret[300];
	DWORD rSize = 300;

	returnValue = sendADPDU(0x00, 0xa4, 0x04, 0x00,Constants::AppletID, sizeof(Constants::AppletID), ret, &rSize, hCard, pioSendPci);


	return returnValue;
}

LONG enryptcbcAES(BYTE *plain, size_t length, BYTE *key, size_t keyLen, BYTE *iv, BYTE *cryptoText) {
	
	std::string cipherText;
	
	AES::Encryption aesEncryption(key, keyLen);
	CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipherText));
	stfEncryptor.Put(plain, length);
	stfEncryptor.MessageEnd();

	memcpy(cryptoText, cipherText.c_str(), length);

	return 0; 

}


LONG decryptcbcAES(BYTE *cryptoText, size_t length, BYTE *key, size_t keyLen, BYTE *iv, BYTE *plain) {




	CBC_Mode< AES >::Decryption decryptor;
	decryptor.SetKeyWithIV(key, keyLen, iv);
	decryptor.ProcessData(plain, cryptoText, length);


	/*

	std::string plainText;
	AES::Decryption aesDecryption(key, keyLen);
	CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	CryptoPP::StreamTransformationFilter stfEncryptor(cbcDecryption, new StringSink(plainText));
	stfEncryptor.Put(cryptoText, length);
	stfEncryptor.MessageEnd();
	*/

	//memcpy(plain, plainText.c_str(), length);

	return 0;

}

LONG computeDHexponentation(BYTE *exponent, int expLength, BYTE *generator, int genLength, BYTE *output,size_t outLength) {

	mpi randA;
	mpi_init(&randA);
	mpi_read_binary(&randA, exponent, expLength);


	mpi modulo;
	mpi_init(&modulo);
	mpi_read_binary(&modulo, SmartCard::Constants::DH_MODULO, SmartCard::Constants::DH_MODULO_SIZE);

	mpi gen;
	mpi_init(&gen);
	mpi_read_binary(&gen, generator, genLength);


	mpi result;
	mpi_init(&result);
	mpi_exp_mod(&result, &gen, &randA, &modulo, NULL);

	mpi_write_binary(&result, output, outLength);


	mpi_free(&modulo);
	mpi_free(&gen);
	mpi_free(&result);

	return 0; 
}

unsigned int SmartCard::SmartCard::deriveKey(BYTE * output, BYTE * pin) {

	PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
	pbkdf2.DeriveKey(output, Constants::AESKeyLength, 0, NULL, 0, Constants::salt, Constants::saltLength, Constants::PBKDFIterations, 0);

	return 0;
}

bool SmartCard::SmartCard::isReaderAvailable() {


	return 1;
}

bool SmartCard::SmartCard::isSmartCardAvailable() {
	return 1;
}


LONG hashAndXor(BYTE *input, BYTE *output, size_t length) {
	
	BYTE hash[SHA256::DIGESTSIZE];

	SHA256 sha;

	sha.CalculateDigest(hash, input, length);

	fprintf(f, "\n");
	fprintf(f, "Hash before xor :\n");

	for (int i = 0; i < 32; i++) {
		fprintf(f, "%02X ", hash[i]);
	}
	fprintf(f, "\n");

	for (int i = 0; i < SHA256::DIGESTSIZE / 2; i++) {
		output[i] = hash[i] ^ hash[i + SHA256::DIGESTSIZE / 2];
	}
	
	return 0;
}


LONG SmartCard::SmartCard::buildChannel(BYTE *pin, DWORD pin_length, BYTE *iv, SCARDHANDLE *hCard, SCARD_IO_REQUEST *pioSendPci, BYTE *establishedKey) {

	f = fopen("C:\\Users\\Public\\Documents\\output.txt", "w");

	//select applet on card
	SmartCard::selectApplet(hCard, pioSendPci);
	
	//generate b and compute value B 
	BYTE randomBuff[crypt::Constants::keyForSmartCard_size];
	BYTE ValueB[Constants::DH_MODULO_SIZE];


	//debug DELETE!!
	memset(randomBuff, 0x00, crypt::Constants::keyForSmartCard_size - 1);
	memset(randomBuff + (crypt::Constants::keyForSmartCard_size - 1), 0x01, 1);

	OS_GenerateRandomBlock(true, randomBuff, crypt::Constants::keyForSmartCard_size);
	computeDHexponentation(randomBuff, crypt::Constants::keyForSmartCard_size, &Constants::DH_generator,1, ValueB, Constants::DH_MODULO_SIZE);


	//derive key (add pin)
	//BYTE derivedKEY[Constants::DerivedKeyLength];
	//deriveKey(derivedKEY, NULL);
	
	//testing only
	BYTE derivedKEY[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

	//enrypt value B with derived key and send it to card
	BYTE encryptedValueB[Constants::DH_MODULO_SIZE];
	enryptcbcAES(ValueB, Constants::DH_MODULO_SIZE, derivedKEY, Constants::AESKeyLength, iv, encryptedValueB);

	//-------TESTING--------

	fprintf(f, "\n");
	fprintf(f, "before:\n");

	for (int i = 0; i < 192; i++) {
		fprintf(f, "%02X ", ValueB[i]);
	}
	fprintf(f, "\n");

	//-------TESTING--------

	DWORD lengthOfEncryptedA = Constants::DH_MODULO_SIZE;
	BYTE encryptedValueA[Constants::DH_MODULO_SIZE];
	SmartCard::sendADPDU(Constants::appletCLA, Constants::INS_BuildChannel, Constants::DH_MODULO_SIZE, 0x00, encryptedValueB, Constants::DH_MODULO_SIZE, encryptedValueA, &lengthOfEncryptedA, hCard, pioSendPci);
	
	//------------------------------
	fprintf(f, "\n");
	fprintf(f, "Encrypted A:\n");

	for (int i = 0; i < 192; i++) {
		fprintf(f, "%02X ", encryptedValueA[i]);
	}
	fprintf(f, "\n");

	//------------------------------


	//Decrypt value A from card
	BYTE ValueA[Constants::DH_MODULO_SIZE];
	decryptcbcAES(encryptedValueA, Constants::DH_MODULO_SIZE, derivedKEY, Constants::AESKeyLength, iv, ValueA);

	fprintf(f, "\n");
	fprintf(f, "Decrypted A :\n");

	for (int i = 0; i < 192; i++) {
		fprintf(f, "%02X ", ValueA[i]);
	}
	fprintf(f, "\n");
	
	//compute shared key from by DH protocol with value A from card
	BYTE dhKey[Constants::DH_MODULO_SIZE];
	computeDHexponentation(randomBuff, crypt::Constants::keyForSmartCard_size, ValueA, 192, dhKey, Constants::DH_MODULO_SIZE);
	//computeDHexponentation(ValueA, Constants::DH_MODULO_SIZE, dhKey, Constants::DH_MODULO_SIZE);

	fprintf(f, "\n");
	fprintf(f, "DH key  :\n");

	for (int i = 0; i < 192; i++) {
		fprintf(f, "%02X ", dhKey[i]);
	}
	fprintf(f, "\n");

	BYTE sharedKey[Constants::AESKeyLength];

	//sha 256
	hashAndXor(dhKey, sharedKey, Constants::DH_MODULO_SIZE);

	fprintf(f, "\n");
	fprintf(f, "shared key :\n");

	for (int i = 0; i < 16; i++) {
		fprintf(f, "%02X ", sharedKey[i]);
	}
	fprintf(f, "\n");

	size_t verificationStringLen = Constants::DH_MODULO_SIZE + pin_length;
	size_t padding = 16 - (verificationStringLen % 16);

	BYTE *verificationStr = new BYTE[verificationStringLen + padding];
	
	memcpy(verificationStr, ValueA, Constants::DH_MODULO_SIZE);
	memcpy(verificationStr + Constants::DH_MODULO_SIZE, pin, pin_length);
	memset(verificationStr + verificationStringLen, 0x00, padding);
	
	fprintf(f, "\n");
	fprintf(f, "verification string :\n");

	for (int i = 0; i < verificationStringLen + padding; i++) {
		fprintf(f, "%02X ", verificationStr[i]);
	}
	fprintf(f, "\n");

	BYTE *encryptedVerificationStr = new BYTE[verificationStringLen + padding];
	enryptcbcAES(verificationStr, verificationStringLen + padding, sharedKey, Constants::AESKeyLength, iv, encryptedVerificationStr);

	fprintf(f, "\n");
	fprintf(f, "encrypted verification string :\n");

	for (int i = 0; i < verificationStringLen + padding; i++) {
		fprintf(f, "%02X ", encryptedVerificationStr[i]);
	}
	fprintf(f, "\n");
	
	DWORD checkReturnLen = 300;

	BYTE encryptedCheckBValue[300];

	//check values
	SmartCard::sendADPDU(Constants::appletCLA, Constants::INS_CHECKCHANNEL, Constants::DH_MODULO_SIZE, pin_length, encryptedVerificationStr, verificationStringLen + padding, encryptedCheckBValue, &checkReturnLen, hCard, pioSendPci);
	

	fprintf(f, "\n");
	fprintf(f, "encrypted check B value:\n");

	for (int i = 0; i < 192; i++) {
		fprintf(f, "%02X ", encryptedCheckBValue[i]);
	}
	fprintf(f, "\n");


	BYTE chechBValue[Constants::DH_MODULO_SIZE];
	decryptcbcAES(encryptedCheckBValue, Constants::DH_MODULO_SIZE, sharedKey, Constants::AESKeyLength, iv, chechBValue);


	fprintf(f, "\n");
	fprintf(f, "Decrypted B to compare :\n");

	for (int i = 0; i < 192; i++) {
		fprintf(f, "%02X ", chechBValue[i]);
	}
	fprintf(f, "\n");
	
	if (memcmp(ValueB, chechBValue, Constants::DH_MODULO_SIZE) == 0) {
		
		memcpy(establishedKey, sharedKey, Constants::AESKeyLength);

		fprintf(f, "heureka :\n");
		fclose(f);
		return 0;
	}
	fprintf(f, "FUCK YOUUU:\n");
	fclose(f);

	return 1;
}


LONG SmartCard::SmartCard::encryptKey(byte * pin, DWORD pin_length, byte * key, DWORD key_length, byte * encrypted, DWORD * encryptedKey_length) {
	
	
	encryptDecryptKey(Constants::FETCH_FILEKEY_ENCRYPT, pin, pin_length, key, key_length, encrypted, encryptedKey_length);


	return 0;
}

LONG SmartCard::SmartCard::decryptKey(byte* pin, DWORD pin_length, byte* encryptedKey, DWORD encryptKey_length, byte* decryptedKey, DWORD* decryptedKey_length) {

	encryptDecryptKey(Constants::FETCH_FILEKEY_DECRYPT, pin, pin_length, encryptedKey, encryptKey_length, decryptedKey, decryptedKey_length);

	return 0;
}

LONG SmartCard::SmartCard::encryptDecryptKey(byte mode, byte * pin, DWORD pin_length, byte * key, DWORD key_length, byte * encryptedDecrypted, DWORD * encryptedDecryptedKey_length) {

	LONG status;

	SCARDHANDLE hCard;
	SCARD_IO_REQUEST pioSendPci;

	BYTE sessionKey[Constants::AESKeyLength];

	//inicialize vector (all zeros for now)
	byte iv[AES::BLOCKSIZE];
	for (int i = 0; i < AES::BLOCKSIZE; i++) {
		iv[i] = 0x00;
	}

	

	if (buildChannel(pin, pin_length, iv, &hCard, &pioSendPci, sessionKey) == 0) {

		sendADPDU(Constants::appletCLA, Constants::INS_FETCH_FILEKEY, mode, 0x00, key, key_length, encryptedDecrypted, encryptedDecryptedKey_length, &hCard, &pioSendPci);
		return 0;
	}


	return 1;
}


//TESTING ONLY
LONG SmartCard::SmartCard::testBuildChannel() {

	LONG status;

	SCARDHANDLE hCard;
	SCARD_IO_REQUEST pioSendPci;


	//inicialize vector (all zeros for now)
	byte iv[AES::BLOCKSIZE];
	for (int i = 0; i < AES::BLOCKSIZE; i++) {
		iv[i] = 0x00;
	}


	BYTE key[Constants::AESKeyLength];

	SmartCard::buildChannel(Constants::testPin, 4, iv, &hCard, &pioSendPci, key);

	return 0;
}

