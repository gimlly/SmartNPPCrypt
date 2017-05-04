#ifndef SMARTCARD_H_DEF
#define SMARTCARD_H_DEF

#include <string>
#include <vector>
#include "exception.h"

namespace SmartCard
{
	namespace Constants {
		static BYTE AppletID[] = { 0x73,  0x69,  0x6D,  0x70,  0x6C, 0x65,  0x61,  0x70,  0x70,  0x6C,  0x65,  0x74 };
		static byte appletCLA = 0xb0;
		static byte INS_BuildChannel = 0x71;
		static byte INS_FETCH_FILEKEY = 0x77;
		static byte FETCH_FILEKEY_ENCRYPT = 0x02;
		static byte FETCH_FILEKEY_DECRYPT = 0x01;
		static byte INS_CHECKCHANNEL = 0x73;
		static const size_t DH_MODULO_SIZE = 192;
		static BYTE DH_generator = { 0x02 };
		static BYTE DH_MODULO[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
			0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 04, 0xDD,
			0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
			0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
			0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
			0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
			0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
			0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x23, 0x73, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
		static size_t PBKDFIterations = 10000;
		static const size_t AESKeyLength = 16;
		static BYTE salt[] = { 0xA0, 0xE3, 0xBB, 0x8F, 0x13, 0xB9, 0xDD, 0x05, 0xA0, 0x8D, 0x64, 0xD2, 0x37, 0xFD, 0xD8, 0x0C };
		static size_t saltLength = 16;
		static BYTE successADPU[] = { 0x90, 0x00 };

		static LONG hashAndXor(BYTE *input, BYTE *output, size_t length);
	};

	class SmartCard
	{
	private: 
		//Why does everything have to be so static? .. 

		static LONG sendADPDU(byte cla, byte command, byte p1, byte p2, byte * data, size_t dataSize, LPBYTE returnData, DWORD *rDataLen, SCARDHANDLE *hCard, SCARD_IO_REQUEST *pioSendPci);
		static LONG connectToCard(SCARDHANDLE *hCard, SCARD_IO_REQUEST *pioSendPci);
		static LONG selectApplet(SCARDHANDLE *hCard, SCARD_IO_REQUEST *pioSendPci);
		static unsigned int deriveKey(BYTE *output, BYTE *pin);
		static LONG buildChannel(BYTE *pin, DWORD pin_length, BYTE *iv, SCARDHANDLE *hCard, SCARD_IO_REQUEST *pioSendPci, BYTE *establishedKey);
		static LONG encryptDecryptKey(byte operation, byte * pin, DWORD pin_length, byte * key, DWORD key_length, byte * encrypted, DWORD * encryptedKey_length);
	public:
		

		static LONG testBuildChannel();

		static bool  isReaderAvailable();
		static bool  isSmartCardAvailable();
		static LONG encryptKey(byte * pin, DWORD pin_length, byte * key, DWORD key_length, byte * encrypted, DWORD * encryptedKey_length);
		static LONG decryptKey(byte* pin, DWORD pin_length, byte* encryptedKey, DWORD encryptKey_length, byte* decryptedKey, DWORD* decryptedKey_length);
	};
};

#endif