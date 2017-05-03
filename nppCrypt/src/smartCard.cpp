#include "smartCard.h"
#include <winscard.h>
#include "cryptheader.h"
#include <cryptopp/osrng.h>
#include "bignum.h"
#include <cryptopp\pwdbased.h>
#include "cryptopp\modes.h"
#include "cryptopp\rijndael.h"
#include <string.h>

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

	std::string plainText;

	AES::Decryption aesDecryption(key, keyLen);
	CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	CryptoPP::StreamTransformationFilter stfEncryptor(cbcDecryption, new CryptoPP::StringSink(plainText));
	stfEncryptor.Put(cryptoText, length);
//	stfEncryptor.MessageEnd();



	//memcpy(plain, plainText.c_str(), length);



	return 0;

}

LONG computeDHexponentation(BYTE *input, int length, BYTE *output,size_t outLength) {

	mpi randA;
	mpi_init(&randA);
	mpi_read_binary(&randA, input, length);


	mpi modulo;
	mpi_init(&modulo);
	mpi_read_binary(&modulo, SmartCard::Constants::DH_MODULO, SmartCard::Constants::DH_MODULO_SIZE);

	mpi generator;
	mpi_init(&generator);
	mpi_lset(&generator, 2);


	mpi result;
	mpi_init(&result);
	mpi_exp_mod(&result, &generator, &randA, &modulo, NULL);

	mpi_write_binary(&result, output, outLength);


	mpi_free(&modulo);
	mpi_free(&generator);
	mpi_free(&result);

	return 0; 
}

unsigned int SmartCard::SmartCard::deriveKey(BYTE * output, BYTE * pin) {

	PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
	pbkdf2.DeriveKey(output, Constants::DerivedKeyLength, 0, NULL, 0, Constants::salt, Constants::saltLength, Constants::PBKDFIterations, 0);

	return 0;
}

bool SmartCard::SmartCard::isReaderAvailable() {


	return 1;
}

bool SmartCard::SmartCard::isSmartCardAvailable() {
	return 1;
}



LONG SmartCard::SmartCard::buildChannel(BYTE *pin, DWORD pin_length, BYTE *iv, SCARDHANDLE *hCard, SCARD_IO_REQUEST *pioSendPci, BYTE *establishedKey) {

	f = fopen("C:\\Users\\Public\\Documents\\output.txt", "w");

	//select applet on card
	SmartCard::selectApplet(hCard, pioSendPci);
	
	//generate b and compute value B 
	BYTE randomBuff[crypt::Constants::keyForSmartCard_size];
	BYTE ValueB[Constants::DH_MODULO_SIZE];

	OS_GenerateRandomBlock(true, randomBuff, crypt::Constants::keyForSmartCard_size);
	computeDHexponentation(randomBuff, crypt::Constants::keyForSmartCard_size, ValueB, Constants::DH_MODULO_SIZE);



	//derive key (add pin)
	BYTE derivedKEY[Constants::DerivedKeyLength];
	deriveKey(derivedKEY, NULL);
	
	//enrypt value B with derived key and send it to card
	BYTE encryptedValueB[Constants::DH_MODULO_SIZE];
	enryptcbcAES(ValueB, Constants::DH_MODULO_SIZE, derivedKEY, Constants::DerivedKeyLength, iv, encryptedValueB);


	//DWORD lengthOfEncryptedA = 0;
	//SmartCard::sendADPDU(Constants::appletCLA, Constants::INS_BuildChannel, 0x00, 0x00, encryptedValueB, crypt::Constants::keyForSmartCard_size, encryptedValueB, &lengthOfEncryptedA, hCard, pioSendPci);
	
	/*
	//Decrypt value A from card
	BYTE ValueA[Constants::DerivedKeyLength];
	decryptcbcAES(encryptedValueB, Constants::DerivedKeyLength, derivedKEY, iv, ValueA);

	//compute shared key from by DH frotocol with value A from card
	BYTE sharedKey[Constants::DerivedKeyLength];
	computeDHexponentation(ValueA, Constants::DerivedKeyLength, sharedKey, Constants::DerivedKeyLength);

	size_t verLength = Constants::DerivedKeyLength + pin_length;
	BYTE *verificationStr = new BYTE[verLength];

	
	memcpy(verificationStr, ValueA, Constants::DerivedKeyLength);
	memcpy(verificationStr + Constants::DerivedKeyLength, pin, pin_length);
	
	BYTE *encryptedVerificationStr = new BYTE[verLength];
	enryptcbcAES(verificationStr, verLength, sharedKey, iv, encryptedVerificationStr);

	DWORD checkReturnLen = 0;

	BYTE encryptedCheckBValue[Constants::DerivedKeyLength];

	//check values
	SmartCard::sendADPDU(Constants::appletCLA, Constants::INS_CHECKCHANNEL, 0x00, 0x00, encryptedVerificationStr, verLength, encryptedCheckBValue, &checkReturnLen, hCard, pioSendPci);

	BYTE chechBValue[Constants::DerivedKeyLength];
	decryptcbcAES(encryptedCheckBValue, Constants::DerivedKeyLength, sharedKey, iv, chechBValue);

	
	if (memcmp(ValueB, chechBValue, Constants::DerivedKeyLength) == 0) {
		
		memcpy(establishedKey, sharedKey, Constants::DerivedKeyLength);
		return 0;
	}
	*/
	fclose(f);

	return 0;
}


LONG SmartCard::SmartCard::encryptKey(byte * pin, DWORD pin_length, byte * key, DWORD key_length, byte * encrypted, DWORD * encryptedKey_length) {
	
	LONG status;
	
	SCARDHANDLE hCard;
	SCARD_IO_REQUEST pioSendPci;


	//inicialize vector (all zeros for now)
	byte iv[AES::BLOCKSIZE];
	for (int i = 0; i < AES::BLOCKSIZE; i++) {
		iv[i] = 0x00;
	}
	

	BYTE kii[Constants::DerivedKeyLength];

	buildChannel(Constants::testPin, 4, iv, &hCard, &pioSendPci, kii);

	return 0;
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


	BYTE key[Constants::DerivedKeyLength];

	SmartCard::buildChannel(Constants::testPin, 4, iv, &hCard, &pioSendPci, key);

	return 0;
}



int SmartCard::SmartCard::decryptKey(byte * pin, int pin_length, byte * encryptedKey, int encryptKey_length, byte * decryptedKey, int * decryptedKey_length) {
	return 0;
}
