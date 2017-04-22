#ifndef SMARTCARD_H_DEF
#define SMARTCARD_H_DEF

#include <string>
#include <vector>
#include "exception.h"

namespace SmartCard
{
	class SmartCard
	{
	public:
		static bool  isReaderAvailable();
		static bool  isSmartCardAvailable();
		static byte* encryptKey(byte* pin, int pin_length, byte* key, int key_length, int* encryptedKey_length);
		static byte* decryptKey(byte* pin, int pin_length, byte* encryptedKey, int encryptKey_length, int* decryptedKey_length);
	};
};

#endif