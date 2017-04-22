#include "smartCard.h"

bool SmartCard::SmartCard::isReaderAvailable()
{
	return true;
}

bool SmartCard::SmartCard::isSmartCardAvailable()
{
	return true;
}

byte* SmartCard::SmartCard::encryptKey(byte* pin, byte* key)
{
	return key;
}

byte* SmartCard::SmartCard::decryptKey(byte* pin, byte* encryptedKey)
{
	return encryptedKey;
}
