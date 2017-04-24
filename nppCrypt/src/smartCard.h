#ifndef SMARTCARD_H_DEF
#define SMARTCARD_H_DEF

#include <string>
#include <vector>
#include "exception.h"

namespace SmartCard
{
	class SmartCard
	{
	private: 
		//Why does everything have to be so static? .. 

		static LONG sendADPDU(byte command, byte * data, size_t dataSize, byte *returnData, DWORD rDataLen, SCARDHANDLE hCard, SCARD_IO_REQUEST pioSendPci);
		static LONG connectToCard(SCARDHANDLE *hCard, SCARD_IO_REQUEST *pioSendPci);

	public:
		static LONG selectApplet();
		static bool  isReaderAvailable();
		static bool  isSmartCardAvailable();
		static int encryptKey(byte* pin, int pin_length, byte* key, int key_length, int* encryptedKey_length, byte *encrypted);
		static int decryptKey(byte* pin, int pin_length, byte* encryptedKey, int encryptKey_length, int* decryptedKey_length, byte *decrypted);
	};
};

#endif