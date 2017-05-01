/*
 * PACKAGEID: 73 69 6D 70 6C 65
 * APPLETID:  73 69 6D 70 6C 65 61 70 70 6C 65 74
 */
package applets;

// imports for Javacard API
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class NppCryptApplet extends javacard.framework.Applet {
    
    // MAIN INSTRUCTION CLASS
    final static byte   CLA_SIMPLEAPPLET        = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte   INS_BUILDCHANNEL        = (byte) 0x71;
    final static byte   INS_CHECKCHANNEL        = (byte) 0x73;
    final static byte   INS_SETPIN              = (byte) 0x75;
    final static byte   INS_FETCH_FILEKEY       = (byte) 0x77;
    
    // APDU RESPONSES
    final static short  SW_BAD_DATA             = (short) 0x6555;
    final static short  SW_NEED_PIN             = (short) 0x6922; 
    final static short  SW_BAD_PIN              = (short) 0x6900;

    // CONSTANTS
    final static short  ARRAY_LENGTH            = (short) 0x100;    // 256 bytes
    final static short  AES_BLOCK_LENGTH        = (short) 0x10;     // 16 bytes
    final static short  RANDOM_LENGTH           = (short) 0x20;     // 32 bytes
    final static short  DH_LENGTH               = (short) 0xC0;     // 192 bytes

    // ZERO MACROS
    final static short  SZERO                   = (short) 0x0;
    final static byte   BZERO                   = (byte)  0x0;

    // DIFFIE HELLMAN PARAMETERS ( source: https://tools.ietf.org/html/rfc3526#page-3 )
    final static byte   DH_GENERATOR[]          = new byte[DH_LENGTH];
    final static byte   DH_MODULUS[]            = {
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
    (byte) 0xC9, (byte) 0x0F, (byte) 0xDA, (byte) 0xA2, (byte) 0x21, (byte) 0x68, (byte) 0xC2, (byte) 0x34,
    (byte) 0xC4, (byte) 0xC6, (byte) 0x62, (byte) 0x8B, (byte) 0x80, (byte) 0xDC, (byte) 0x1C, (byte) 0xD1,
    (byte) 0x29, (byte) 0x02, (byte) 0x4E, (byte) 0x08, (byte) 0x8A, (byte) 0x67, (byte) 0xCC, (byte) 0x74,
    (byte) 0x02, (byte) 0x0B, (byte) 0xBE, (byte) 0xA6, (byte) 0x3B, (byte) 0x13, (byte) 0x9B, (byte) 0x22,
    (byte) 0x51, (byte) 0x4A, (byte) 0x08, (byte) 0x79, (byte) 0x8E, (byte) 0x34, (byte) 0x04, (byte) 0xDD,
    (byte) 0xEF, (byte) 0x95, (byte) 0x19, (byte) 0xB3, (byte) 0xCD, (byte) 0x3A, (byte) 0x43, (byte) 0x1B,
    (byte) 0x30, (byte) 0x2B, (byte) 0x0A, (byte) 0x6D, (byte) 0xF2, (byte) 0x5F, (byte) 0x14, (byte) 0x37,
    (byte) 0x4F, (byte) 0xE1, (byte) 0x35, (byte) 0x6D, (byte) 0x6D, (byte) 0x51, (byte) 0xC2, (byte) 0x45,
    (byte) 0xE4, (byte) 0x85, (byte) 0xB5, (byte) 0x76, (byte) 0x62, (byte) 0x5E, (byte) 0x7E, (byte) 0xC6,
    (byte) 0xF4, (byte) 0x4C, (byte) 0x42, (byte) 0xE9, (byte) 0xA6, (byte) 0x37, (byte) 0xED, (byte) 0x6B,
    (byte) 0x0B, (byte) 0xFF, (byte) 0x5C, (byte) 0xB6, (byte) 0xF4, (byte) 0x06, (byte) 0xB7, (byte) 0xED,
    (byte) 0xEE, (byte) 0x38, (byte) 0x6B, (byte) 0xFB, (byte) 0x5A, (byte) 0x89, (byte) 0x9F, (byte) 0xA5,
    (byte) 0xAE, (byte) 0x9F, (byte) 0x24, (byte) 0x11, (byte) 0x7C, (byte) 0x4B, (byte) 0x1F, (byte) 0xE6,
    (byte) 0x49, (byte) 0x28, (byte) 0x66, (byte) 0x51, (byte) 0xEC, (byte) 0xE4, (byte) 0x5B, (byte) 0x3D,
    (byte) 0xC2, (byte) 0x00, (byte) 0x7C, (byte) 0xB8, (byte) 0xA1, (byte) 0x63, (byte) 0xBF, (byte) 0x05,
    (byte) 0x98, (byte) 0xDA, (byte) 0x48, (byte) 0x36, (byte) 0x1C, (byte) 0x55, (byte) 0xD3, (byte) 0x9A,
    (byte) 0x69, (byte) 0x16, (byte) 0x3F, (byte) 0xA8, (byte) 0xFD, (byte) 0x24, (byte) 0xCF, (byte) 0x5F,
    (byte) 0x83, (byte) 0x65, (byte) 0x5D, (byte) 0x23, (byte) 0xDC, (byte) 0xA3, (byte) 0xAD, (byte) 0x96,
    (byte) 0x1C, (byte) 0x62, (byte) 0xF3, (byte) 0x56, (byte) 0x20, (byte) 0x85, (byte) 0x52, (byte) 0xBB,
    (byte) 0x9E, (byte) 0xD5, (byte) 0x29, (byte) 0x07, (byte) 0x70, (byte) 0x96, (byte) 0x96, (byte) 0x6D,
    (byte) 0x67, (byte) 0x0C, (byte) 0x35, (byte) 0x4E, (byte) 0x4A, (byte) 0xBC, (byte) 0x98, (byte) 0x04,
    (byte) 0xF1, (byte) 0x74, (byte) 0x6C, (byte) 0x08, (byte) 0xCA, (byte) 0x23, (byte) 0x73, (byte) 0x27,
    (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
    };

////// SECURE CHANNEL BUILDUP ENVIRONMENT ///////////////////////////

    // Diffie-Hellman
    private     RandomData      m_secureRandom  = null; // this generates secure random data
    private     RSAPrivateKey   m_DHKey         = null; // this stores exponent and modulus for Diffie-Hellman
    private     Cipher          m_DHCipher      = null; // this stores RSA cipher for Diffie-Hellman

    // PBKDF2, Session Key, Pin Storage
    private     AESKey          m_HashKey       = null; // this stores preshared hash of pin
    private     Cipher          m_encryptCipher = null; // this stores AES encrypt cipher
    private     Cipher          m_decryptCipher = null; // this stores AES decrypt cipher
    private     AESKey          m_sessionKey    = null; // this stores secure channel session key
    private     OwnerPIN        m_pin           = null; // this stores pin
    private     MessageDigest   m_hash          = null; // hash of primary session key

/////////////////////////////////////////////////////////////////////

    // INTERNAL STORAGE
    private     AESKey          m_KEK           = null; // this stores Key encryption key
    private     Cipher          m_KEK_Cipher    = null; // Cipher engine for KEK enc/dec
    // TEMPORARY ARRAYS IN RAM
    private     byte            m_ramArray1[]   = null;
    private     byte            m_ramArray2[]   = null;
    // PERSISTENT ARRAY IN EEPROM
    private     byte            m_dataArray1[]  = null;
    private     byte            m_dataArray2[]  = null;

    /**
     * NppCryptApplet constructor
     */
    protected NppCryptApplet(byte[] buffer, short offset, byte length)
    {
        short dataOffset = offset;
        boolean isOP2 = false;

        if(length > 9) {
            
            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset (Length of data)
            dataOffset += (short)( 1 + buffer[dataOffset]);
            // go to proprietary data
            dataOffset++;

            //Init EEPROM arrays
            m_dataArray1 = new byte[ARRAY_LENGTH];
            m_dataArray2 = new byte[ARRAY_LENGTH];

            // Copy install params to EEPROM.
            // Install params are 36 B long:
            // 4 B  PIN
            // 16 B hash (m_HashKey)
            // 16 B KEK  (m_KEK)
            Util.arrayCopyNonAtomic(buffer, dataOffset, m_dataArray1, SZERO, buffer[(byte)(dataOffset - 1)]);
            
            //Set generator value
            DH_GENERATOR[(short) (DH_LENGTH - 1)] = (byte) 0x02;

            // INITIALIZE RNG, RSA, KEY
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            m_DHCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            m_DHKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1536, false);
            
            // INIT HASH ENGINE
            m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
                    
            // CREATE HASHKEY OBJECT, DEFINE AND INIT ENCRYPTION ALGORITHM
            m_HashKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            m_HashKey.setKey(m_dataArray1, (short) 4);
            m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_encryptCipher.init(m_HashKey, Cipher.MODE_ENCRYPT);
            m_decryptCipher.init(m_HashKey, Cipher.MODE_DECRYPT);
            
            // CREATE SESSION KEY OBJECT
            m_sessionKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            
            // CREATE KEK OBJECT, KEK CIPHER ENGINE
            m_KEK = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            m_KEK_Cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            
            //store initial PIN, with tryLimit and maxPINsize
            m_pin = new OwnerPIN((byte) 3, (byte) 16);
            m_pin.update(m_dataArray1, BZERO, (byte) 4);
            
            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray1 = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
            m_ramArray2 = JCSystem.makeTransientByteArray(ARRAY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
            
            // Set EEPROM to zeros. Other data will be stored in EEPROM
            Util.arrayFillNonAtomic(m_dataArray1, SZERO, ARRAY_LENGTH, BZERO);

            // update flag
            isOP2 = true;

        } else {}
        register();
    }

    /**
     * Method installing the applet.
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        // applet  instance creation 
        new NppCryptApplet(bArray, bOffset, bLength);
    }
    
    /**
     * Method performed on applet selection
     * @return return code
     */
    public boolean select()
    {
        //wipe arrays
        Util.arrayFillNonAtomic(m_dataArray1, SZERO, ARRAY_LENGTH, BZERO);
        Util.arrayFillNonAtomic(m_dataArray2, SZERO, ARRAY_LENGTH, BZERO);
        return true;
    }
    
    /**
     * Method performed on applet deselection
     */
    public void deselect()
    {
        return;
    }

    /**
     * Method processing an incoming APDU.
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    public void process(APDU apdu) throws ISOException
    {
        // get the APDU buffer
        byte[] apduBuffer = apdu.getBuffer();

        // ignore the applet select command dispached to the process
        if (selectingApplet())
            return;

        // APDU instruction parser
        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
            switch ( apduBuffer[ISO7816.OFFSET_INS] )
            {
                case INS_BUILDCHANNEL:  BuildChannel(apdu); break;
                case INS_CHECKCHANNEL:  CheckChannel(apdu); break;
                case INS_SETPIN:        SetPIN(apdu);       break;
                case INS_FETCH_FILEKEY: FetchFileKey(apdu); break;
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;
            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    
    /**
     * Establish Secure Channel
     * @param apdu APDU encrypted by preshared secret: receive B, send A
     */
    void BuildChannel(APDU apdu) {
        byte[]      apdubuf = apdu.getBuffer();
        short       dataLen = apdu.setIncomingAndReceive();
        short       lenA, lenB;
        byte        pad;
        
        //Note: Diffie-Hellman using RSA works better when using MODE_DECRYPT
        //      The result is still the same though
        
        //Generate random exponent
        m_secureRandom.generateData(m_ramArray1, SZERO, RANDOM_LENGTH);
      
        //Compute A (Fill RSAKey with exponent, modulus, init cipher, decrypt)
        m_DHKey.setExponent(m_ramArray1, SZERO, RANDOM_LENGTH);
        m_DHKey.setModulus(DH_MODULUS, SZERO, DH_LENGTH);
        m_DHCipher.init(m_DHKey, Cipher.MODE_DECRYPT);
        lenA = m_DHCipher.doFinal(DH_GENERATOR, SZERO, DH_LENGTH, m_ramArray1, SZERO);
        
        // store A in permanent memory, to validate channel later
        Util.arrayCopyNonAtomic(m_ramArray1, SZERO, m_dataArray1, (short) (DH_LENGTH - lenA), lenA);
        
        //PKCS7 padding (probably not necessarry, but still)
        //calculate pad length and value
        pad = (byte) (16 - (lenA % 16));
        //if it's aligned already, we add whole 16 block
        if (pad == BZERO) {
            pad = (byte) 16;
        }
        //add padding bytes
        for (short i = 0; i < pad; i++) {
            m_ramArray1[(short) (lenA + i)] = pad;
        }

        //(AES) Encrypt A with preshared secret, store it in ram array
        m_encryptCipher.doFinal(m_ramArray1, SZERO, (short) (lenA + pad), m_ramArray2, SZERO);

        //(AES) Decrypt & copy B to RAM (from plugin to card)
        m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray1, SZERO);
        lenB = apdubuf[ISO7816.OFFSET_P1];
        
        //store B in permanent memory, to validate channel later
        Util.arrayCopyNonAtomic(m_ramArray1, SZERO, m_dataArray2, (short) (DH_LENGTH - lenB), lenB);
        
        //Copy encrypted A to APDU (from card to plugin), set padless data length
        Util.arrayCopyNonAtomic(m_ramArray2, SZERO, apdubuf, ISO7816.OFFSET_CDATA, (short) (lenA + pad));
        apdubuf[ISO7816.OFFSET_P1] = (byte) lenA;
        
        //need to pad ramArray1 from the left with zeros, wipe ramArray2
        Util.arrayCopyNonAtomic(m_ramArray1, SZERO, m_ramArray1, (short) (DH_LENGTH - lenB), lenB);
        Util.arrayFillNonAtomic(m_ramArray1, SZERO, (short) (DH_LENGTH - lenB - 1), BZERO);
        Util.arrayFillNonAtomic(m_ramArray2, SZERO, ARRAY_LENGTH, BZERO);
        
        //(RSA) compute Primary Session Key
        m_DHCipher.init(m_DHKey, Cipher.MODE_DECRYPT); //init engine again to work properly
        lenA = m_DHCipher.doFinal(m_ramArray1, SZERO, DH_LENGTH, m_ramArray2, SZERO);
        
        //(SHA) hash primary session key into m_ramArray1
        m_hash.doFinal(m_ramArray2, SZERO, lenA, m_ramArray1, SZERO);
        
        //XOR it inside m_ramArray1
        for (short i = 0; i < (short) 16; i++) {
            m_ramArray1[i] ^= m_ramArray1[(short)(i + AES_BLOCK_LENGTH)];
        }
        
        //insert key into KeyObject - sessionKey, init cipher
        m_sessionKey.setKey(m_ramArray1, SZERO);
        m_encryptCipher.init(m_sessionKey, Cipher.MODE_ENCRYPT);
        m_decryptCipher.init(m_sessionKey, Cipher.MODE_DECRYPT);
        
        //send APDU with encrypted A
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (lenA + pad));
    }
    
    /**
     * Method checks for correct PIN and Secure Channel
     * @param apdu APDU encrypted by Session Key: receive A, send B
     * P1 = Length of A
     * P2 = Length of PIN
     */
    void CheckChannel(APDU apdu) {
        byte[]  apdubuf = apdu.getBuffer();
        short   dataLen = apdu.setIncomingAndReceive();
        
        //decrypt incoming APDU
        m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray1, SZERO);
        
        //validate pin
        if (m_pin.check(m_ramArray1, ISO7816.OFFSET_P1, ISO7816.OFFSET_P2) == false) {
            ISOException.throwIt(SW_BAD_PIN);            
        } else {
            //validate A
            for (short i = 0; i < ISO7816.OFFSET_P1; i++) {
                if (m_dataArray1[i] != m_ramArray1[i])
                    ISOException.throwIt(SW_BAD_DATA);
            }
            
            //encrypt B with session key, put it into APDU buffer
            m_encryptCipher.doFinal(m_dataArray2, SZERO, DH_LENGTH, apdubuf, ISO7816.OFFSET_CDATA);
            
            //prepare APDU to send. THESE 192 BYTES ARE NOT PADDED!
            apdubuf[ISO7816.OFFSET_P1] = (byte) DH_LENGTH;
            
            //Send APDU with encrypted B
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, DH_LENGTH);
        }
    }

    /**
     * Send FileKey in APDU, so card can encrypt/decrypt it using KEK
     * @param apdu UNPADDED 16 B FileKey
     * P1:
     * MODE_ENCRYPT = 2
     * MODE_DECRYPT = 1
     */
    void FetchFileKey(APDU apdu) {
        byte[]  apdubuf = apdu.getBuffer();
        short   dataLen = apdu.setIncomingAndReceive();

        if (m_pin.isValidated()) {
            //Decrypt using session key, 16 bytes
            m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, AES_BLOCK_LENGTH, m_ramArray1, SZERO);
            //init KEK cipher with needed mode
            m_KEK_Cipher.init(m_KEK, apdubuf[ISO7816.OFFSET_P1]);
            //encrypt/decrypt FileKey using KEK
            m_KEK_Cipher.doFinal(m_ramArray1, SZERO, AES_BLOCK_LENGTH, apdubuf, ISO7816.OFFSET_CDATA);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, AES_BLOCK_LENGTH);
        } else {
            ISOException.throwIt(SW_NEED_PIN);
        }
        

    }
    
    /**
     * Change the value of PIN
     * @param apdu input APDU, output APDU
     * P1 - length of new PIN (should be between 4 and 16)
     * P2 - length of new H(PIN) (should be 16)
     * padded to multiple of 16, encrypted by session key
     */
    void SetPIN(APDU apdu) {
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();

        if (m_pin.isValidated()) {
            //Decrypt using Session Key
            m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray1, SZERO);
            //Update PIN value
            m_pin.update(m_ramArray1, SZERO, apdubuf[ISO7816.OFFSET_P1]);
            //Update Shared Secret Key
            m_HashKey.setKey(m_ramArray1, apdubuf[ISO7816.OFFSET_P1]);
            //Init ciphers with new Key
            m_encryptCipher.init(m_HashKey, Cipher.MODE_ENCRYPT);
            m_decryptCipher.init(m_HashKey, Cipher.MODE_DECRYPT);
        } else {
            ISOException.throwIt(SW_NEED_PIN);
        }
    }
}
