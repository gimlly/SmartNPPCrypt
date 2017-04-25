#include "smartCard.h"
 

// 0x00, 0xa4,  0x04,  0x00,  0x0b, 
BYTE cmd1[] = {0x73,  0x69,  0x6D,  0x70,  0x6C, 0x65,  0x61,  0x70,  0x70,  0x6C,  0x65,  0x74 };

LONG SmartCard::SmartCard::sendADPDU(byte cla, byte command, byte p1, byte p2, byte * data, size_t dataSize, byte *returnData, DWORD rDataLen, SCARDHANDLE hCard, SCARD_IO_REQUEST pioSendPci) {
	LONG returnValue; 

	byte apdu[258];
	apdu[0] = cla;
	apdu[1] = command;
	apdu[2] = p1;
	apdu[3] = p2;
	
	if (dataSize > 0) {
		apdu[3] = (byte)dataSize;

		for (size_t count = 0; count < dataSize; count++) {
			apdu[count + 5] = data[count];
		}
	}

	

	returnValue = SCardTransmit(hCard, &pioSendPci, apdu, dataSize + 4, NULL, returnData, &rDataLen);
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



LONG SmartCard::SmartCard::selectApplet() {
	LONG status;
	SCARDHANDLE hCard;
	SCARD_IO_REQUEST pioSendPci;

	status = connectToCard(&hCard, &pioSendPci);
	if (status != 0) {
		return 1;
	}

	byte ret[300];
	DWORD rSize;

	sendADPDU(0x00, 0xa4, 0x04, 0x00,Constants::AppletID, sizeof(Constants::AppletID), ret, rSize, hCard, pioSendPci);


	return 0;
}

bool SmartCard::SmartCard::isReaderAvailable()
{
	return 1;
}

bool SmartCard::SmartCard::isSmartCardAvailable()
{
	return 1;
}

int SmartCard::SmartCard::encryptKey(byte * pin, int pin_length, byte * key, int key_length, byte * encrypted, int * encryptedKey_length) {

	LONG status;
	SCARDHANDLE hCard;
	SCARD_IO_REQUEST pioSendPci;

	status = connectToCard(&hCard,&pioSendPci);
	if (status != 0) {
		return 1;
	}




	return 0;
}

int SmartCard::SmartCard::decryptKey(byte * pin, int pin_length, byte * encryptedKey, int encryptKey_length, byte * decryptedKey, int * decryptedKey_length)
{
	return 0;
}
