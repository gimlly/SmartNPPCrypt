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
		static byte* encryptKey(byte* pin, byte* key);
		static byte* decryptKey(byte* pin, byte* encryptedKey);
	};
};

#endif