#include "smartCard.h"
#include <winscard.h>
#include "cryptheader.h"
#include <cryptopp/osrng.h>
#include "bignum.h"
#include <cryptopp\pwdbased.h>


#include <iostream>
#include <fstream>
using namespace std;


LONG SmartCard::SmartCard::sendADPDU(byte cla, byte command, byte p1, byte p2, byte * data, size_t dataSize, LPBYTE returnData, LPDWORD rDataLen, SCARDHANDLE *hCard, SCARD_IO_REQUEST *pioSendPci) {
	LONG returnValue; 

	byte apdu[258];
	apdu[0] = cla;
	apdu[1] = command;
	apdu[2] = p1;
	apdu[3] = p2;



	if (dataSize > 0) {
		apdu[4] = (byte)dataSize - 1;

		for (size_t count = 0; count < dataSize; count++) {
			apdu[count + 5] = data[count];
		}
	}


	FILE *f = fopen("C:\\Users\\Public\\Documents\\output.txt", "w");

	for (int i = 0; i < dataSize + 5; i++) {
		fprintf(f, "%02X ", apdu[i]);
	}

	returnValue = SCardTransmit(*hCard, pioSendPci, apdu, dataSize + 5, NULL, returnData, rDataLen);

	//For DEBUG only!

	fprintf(f, "\n" );
	fprintf(f, "size of return data is: %lu\n", *rDataLen);

	for (int i = 0; i < *rDataLen; i++) {
		fprintf(f,"%02X ", returnData[i]);
	}

	fclose(f);

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
	DWORD rSize = 8;

	returnValue = sendADPDU(0x00, 0xa4, 0x04, 0x00,Constants::AppletID, sizeof(Constants::AppletID), ret, &rSize, hCard, pioSendPci);


	return returnValue;
}

unsigned int SmartCard::SmartCard::derivateKey(BYTE * output, BYTE * pin) {

	CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
	pbkdf2.DeriveKey(output, Constants::DerivedKeyLength, 0, NULL, 0, Constants::salt, Constants::saltLength, Constants::PBKDFIterations, 0);

	return 0;
}

bool SmartCard::SmartCard::isReaderAvailable() {


	return 1;
}

bool SmartCard::SmartCard::isSmartCardAvailable() {
	return 1;
}

int SmartCard::SmartCard::encryptKey(byte * pin, int pin_length, byte * key, int key_length, byte * encrypted, int * encryptedKey_length) {
	
	LONG status;
	
	SCARDHANDLE hCard;
	SCARD_IO_REQUEST pioSendPci;


	//select applet on card
	SmartCard::selectApplet(&hCard, &pioSendPci);

	BYTE randomBuff[crypt::Constants::keyForSmartCard_size];
	BYTE randomB[crypt::Constants::keyForSmartCard_size];

	CryptoPP::OS_GenerateRandomBlock(true, randomBuff, crypt::Constants::keyForSmartCard_size);

	mpi randA;
	mpi_init(&randA);
	mpi_read_binary(&randA, randomBuff, crypt::Constants::keyForSmartCard_size);

	mpi modulo;
	mpi_init(&modulo);
	mpi_read_binary(&modulo, Constants::DH_MODULO, Constants::DH_MODULO_SIZE);


	mpi generator;
	mpi_init(&generator);
	mpi_lset(&generator, 2);
	

	mpi valueA;
	mpi_init(&valueA);
	mpi_exp_mod(&valueA, &generator, &randA, &modulo, NULL);

	BYTE derivedKEY[Constants::DerivedKeyLength];

	//derive key (add pin)
	SmartCard::derivateKey(derivedKEY, NULL);

	




	//SmartCard::sendADPDU(Constants::appletCLA, Constants::INS_BuildChannel, crypt::Constants::keyForSmartCard_size, 0x00, randomBuff, crypt::Constants::keyForSmartCard_size, )


	return 0;
}

int SmartCard::SmartCard::decryptKey(byte * pin, int pin_length, byte * encryptedKey, int encryptKey_length, byte * decryptedKey, int * decryptedKey_length) {
	return 0;
}
