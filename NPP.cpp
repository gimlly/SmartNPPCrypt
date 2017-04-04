// NPP.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <winscard.h>

int main(void)
{
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

	return 0;
}