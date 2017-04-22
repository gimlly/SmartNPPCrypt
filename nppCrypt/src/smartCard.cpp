#include "smartCard.h"

bool SmartCard::SmartCard::isReaderAvailable()
{
	return true;
}

bool SmartCard::SmartCard::isSmartCardAvailable()
{
	return true;
}

byte* SmartCard::SmartCard::encryptKey(byte* pin, int pin_length, byte* key, int key_length, int* encryptedKey_length)
{
	return key;
}

byte* SmartCard::SmartCard::decryptKey(byte* pin, int pin_length, byte* encryptedKey, int encryptKey_length, int* decryptedKey_length)
{
	return encryptedKey;
}
