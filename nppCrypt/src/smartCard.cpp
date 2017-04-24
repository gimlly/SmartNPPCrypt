#include "smartCard.h"
#include <winscard.h> 

// 0x00, 0xa4,  0x04,  0x00,  0x0b, 
BYTE cmd1[] = {0x73,  0x69,  0x6D,  0x70,  0x6C, 0x65,  0x61,  0x70,  0x70,  0x6C,  0x65,  0x74 };

LONG SmartCard::SmartCard::sendADPDU(byte command, byte * data, size_t dataSize, byte *returnData, DWORD rDataLen,SCARDHANDLE hCard, SCARD_IO_REQUEST pioSendPci) {
	LONG returnValue; 

	byte apdu[256];
	apdu[0] = 0x00;
	apdu[1] = command;
	apdu[2] = apdu[3] = 0x00;
	apdu[3] = (byte)dataSize;

	for (size_t count = 0; count < dataSize; count++) {
		apdu[count + 5] = data[count];
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

	sendADPDU(0xa4, cmd1, sizeof(cmd1), ret, 300, hCard, pioSendPci);


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


/*


LONG rv;

SCARDCONTEXT hContext;
LPTSTR mszReaders;
SCARDHANDLE hCard;
DWORD dwReaders, dwActiveProtocol, dwRecvLength;

SCARD_IO_REQUEST pioSendPci;
BYTE pbRecvBuffer[258];

BYTE cmd1[] = { 0x00, 0xa4,  0x04,  0x00,  0x0b, 0x73,  0x69,  0x6D,  0x70,  0x6C, 0x65,  0x61,  0x70,  0x70,  0x6C,  0x65,  0x74 };

unsigned int i;

rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);

dwReaders = SCARD_AUTOALLOCATE;
rv = SCardListReaders(hContext, NULL, (LPTSTR)&mszReaders, &dwReaders);

_tprintf(mszReaders);
printf("\n");

rv = SCardConnect(hContext, mszReaders, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);

switch (dwActiveProtocol)
{
case SCARD_PROTOCOL_T0:
pioSendPci = *SCARD_PCI_T0;
break;

case SCARD_PROTOCOL_T1:
pioSendPci = *SCARD_PCI_T1;
break;
}

dwRecvLength = sizeof(pbRecvBuffer);
rv = SCardTransmit(hCard, &pioSendPci, cmd1, sizeof(cmd1),
NULL, pbRecvBuffer, &dwRecvLength);

printf("response: ");

for (i = 0; i < dwRecvLength; i++)
{
printf("%02X ", pbRecvBuffer[i]);
}
printf("\n");

dwRecvLength = sizeof(pbRecvBuffer);

rv = SCardDisconnect(hCard, SCARD_LEAVE_CARD);
rv = SCardFreeMemory(hContext, mszReaders);
rv = SCardReleaseContext(hContext);

*/

