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
    final static byte CLA_SIMPLEAPPLET              = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_BUILDCHANNEL              = (byte) 0x71;
    final static byte INS_CHECKCHANNEL              = (byte) 0x73;
    final static byte INS_SETPIN                    = (byte) 0x75;
    final static byte INS_ENCRYPT_FILEKEY           = (byte) 0x85;
    final static byte INS_DECRYPT_FILEKEY           = (byte) 0x87;
    
    // APDU RESPONSES
    final static short SW_BAD_TEST_DATA_LEN         = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD            = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD    = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE      = (short) 0x6711;
    final static short SW_NEED_PIN                  = (short) 0x6922; 
    final static short SW_OK_PIN                    = (short) 0x6911;
    final static short SW_BAD_PIN                   = (short) 0x6900;
    final static short SW_CHALLENGE_LENGTH_BAD      = (short) 0x6969;

    // CONSTANTS
    final static short ARRAY_LENGTH                 = (short) 0xff; //255 bytes
    final static short AES_BLOCK_LENGTH             = (short) 0x10; //16 bytes
    final static short HASH_LENGTH                  = (short) 0x20; //32 bytes
    final static short RANDOM_LENGTH                = (short) 0x20; //32 bytes
    final static short DH_GENERATOR_LENGTH          = (short) 0xC0; //192 bytes //was 1
    final static short DH_MODULUS_LENGTH            = (short) 0xC0; //192 bytes
    
    final static short SZERO                        = (short) 0x0;
    final static byte  BZERO                        = (byte)  0x0;

    //Generator and Modulus are public, no need to hide them
    final static byte DH_GENERATOR[]                = new byte[DH_GENERATOR_LENGTH];
    
    //source:
    //https://tools.ietf.org/html/rfc3526#page-3
    final static byte DH_MODULUS[]                  = {
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
    private   RandomData     m_secureRandom = null; //this generates secure random data
    private   RSAPrivateKey  m_DHKey = null;        //this stores exponent and modulus for Diffie-Hellman
    private   Cipher         m_DHCipher = null;     //this stores RSA cipher for Diffie-Hellman

    // PBKDF2, Session Key, Pin Storage
    private   AESKey         m_HashKey = null;      //this stores preshared hash of pin
    private   Cipher         m_encryptCipher = null;//this stores AES encrypt cipher
    private   Cipher         m_decryptCipher = null;//this stores AES decrypt cipher
    private   AESKey         m_sessionKey = null;   //this stores secure channel session key
    private   OwnerPIN       m_pin = null;          //this stores pin
    private   MessageDigest  m_hash = null;         //hash of primary session key

/////////////////////////////////////////////////////////////////////

    // INTERNAL STORAGE
    private   AESKey         m_KEK = null;          //this stores Key encryption key

    private   short          m_apduLogOffset = (short) 0;
    // TEMPORARY ARRAYS IN RAM
    private   byte           m_ramArray1[]    = null;
    private   byte           m_ramArray2[]    = null;
    // PERSISTENT ARRAY IN EEPROM
    private   byte           m_dataArray[]   = null;


    //not sure if this is correct
    private Cipher       m_aes = null;

    /**
     * LabakApplet default constructor
     * Only this class's install method should create the applet object.
     */
    protected NppCryptApplet(byte[] buffer, short offset, byte length)
    {
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if(length > 9) {
            // Install parameter detail. Compliant with OP 2.0.1.

            // | size | content
            // |------|---------------------------
            // |  1   | [AID_Length]
            // | 5-16 | [AID_Bytes]
            // |  1   | [Privilege_Length]
            // | 1-n  | [Privilege_Bytes] (normally 1Byte)
            // |  1   | [Application_Proprietary_Length]
            // | 0-m  | [Application_Proprietary_Bytes]

            // shift to privilege offset
            dataOffset += (short)( 1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short)( 1 + buffer[dataOffset]);

            // go to proprietary data
            dataOffset++;

            //Copy proprietary data to eeprom. 4 bytes of PIN, 16 bytes of Key
            m_dataArray = new byte[ARRAY_LENGTH];
            
            //Pin = 4 to 8 bytes
            byte[] arrayPin = {(byte)0x03, (byte)0x01, (byte)0x07, (byte)0x04};
            //pbkdf = 20 (truncated to 16 bytes)
            byte[] arrayKey = {(byte)0xfe, (byte)0xff, (byte)0xff, (byte)0xff, 
                               (byte)0xfe, (byte)0xff, (byte)0xff, (byte)0xff, 
                               (byte)0xfe, (byte)0xff, (byte)0xff, (byte)0xff, 
                               (byte)0xfe, (byte)0xff, (byte)0xff, (byte)0xff,
                               (byte)0xfe, (byte)0xff, (byte)0xff, (byte)0xff}; //last 4 bytes are cut off
            Util.arrayCopyNonAtomic(arrayPin, (short) 0, m_dataArray, (short) 0, (short) 0x04);
            Util.arrayCopyNonAtomic(arrayKey, (short) 0, m_dataArray, (short) 4, (short) 0x10);
//            Util.arrayCopyNonAtomic(buffer, dataOffset, m_dataArray, (short) 0, buffer[(byte)(dataOffset - 1)]);
            
            DH_GENERATOR[(short) (DH_GENERATOR_LENGTH - 1)] = (byte) 0x02;

            // INITIALIZE RNG, RSA, KEY
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            m_DHCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            m_DHKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1536, false);
            
            // INIT HASH ENGINE
            m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
                    
            // CREATE HASHKEY OBJECT, DEFINE AND INIT ENCRYPTION ALGORITHM
            m_HashKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            m_HashKey.setKey(arrayKey, (short) 4);
            m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_encryptCipher.init(m_HashKey, Cipher.MODE_ENCRYPT);
            m_decryptCipher.init(m_HashKey, Cipher.MODE_DECRYPT);
            
            // CREATE SESSION KEY OBJECT
            m_sessionKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            /*set value here*/
            
            // CREATE KEK OBJECT
            m_KEK = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            /*set value here*/
            
            //store initial PIN, with tryLimit and maxPINsize
            m_pin = new OwnerPIN((byte) 5, (byte) 16);
            m_pin.update(m_dataArray, (byte) 0, (byte) 4);
            
            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray1 = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);
            m_ramArray2 = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);
            
            // Set EEPROM to 0s. No data needs to be stored in EEPROM.
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, length, (byte) 0);

            // update flag
            isOP2 = true;

        } else {
            //Nothing for now, installation is probably invalid
        }
        // register this instance
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

    public boolean select()
    {
        return true;
    }

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
        //short dataLen = apdu.setIncomingAndReceive();
        //Util.arrayCopyNonAtomic(apduBuffer, (short) 0, m_dataArray, m_apduLogOffset, (short) (5 + dataLen));
        //m_apduLogOffset = (short) (m_apduLogOffset + 5 + dataLen);

        // ignore the applet select command dispached to the process
        if (selectingApplet())
            return;

        // APDU instruction parser
        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
            switch ( apduBuffer[ISO7816.OFFSET_INS] )
            {
                case INS_BUILDCHANNEL: BuildChannel(apdu); break;
                case INS_CHECKCHANNEL: CheckChannel(apdu); break;
                case INS_SETPIN: SetPIN(apdu); break;
                case INS_ENCRYPT_FILEKEY: EncryptFileKey(apdu); break;
                case INS_DECRYPT_FILEKEY: DecryptFileKey(apdu); break;
                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;

            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    
    /**
     * Compute Diffie-Hellman Session Key, send data to plugin to compute as well
     * @param apdu encrypted by preshared secret: receive B, send A
     */
    void BuildChannel(APDU apdu) {
        byte[]      apdubuf = apdu.getBuffer();
        short       dataLen = apdu.setIncomingAndReceive();
        short       lenA, lenB;
        byte        pad;
        
        //Generate exponent (not sure about the length, but 0x20 = 32 bytes = 256 bits
        m_secureRandom.generateData(m_ramArray1, SZERO, RANDOM_LENGTH);
      
        //Compute A (Fill RSAKey with exponent, modulus, init cipher, encrypt)
        m_DHKey.setExponent(m_ramArray1, SZERO, RANDOM_LENGTH);
        m_DHKey.setModulus(DH_MODULUS, SZERO, DH_MODULUS_LENGTH);
        m_DHCipher.init(m_DHKey, Cipher.MODE_DECRYPT); //works similar to encrypt mode and witohout errors
        // (RSA)
        lenA = m_DHCipher.doFinal(DH_GENERATOR, SZERO, DH_GENERATOR_LENGTH, m_ramArray1, SZERO);
        
        //PKCS7 padding
        //calculate pad length and value
        pad = (byte) (16 - (lenA % 16));
        //if it's aligned already, we add whle 16 block
        if (pad == BZERO) {
            pad = (byte) 16;
        }
        //add that many padding bytes
        for (short i = 0; i < pad; i++) {
            m_ramArray1[(short) (lenA + i)] = pad;
        }

        //(AES) Encrypt A with preshared secret, store it in secondary ram array
        m_encryptCipher.doFinal(m_ramArray1, SZERO, (short) (lenA + pad), m_ramArray2, SZERO);

        //(AES) Decrypt & copy B to RAM (from plugin to card)
        m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray1, SZERO);
        lenB = apdubuf[ISO7816.OFFSET_P1];
        
        //Copy encrypted A to APDU (from card to plugin), set padless data length
        Util.arrayCopyNonAtomic(m_ramArray2, SZERO, apdubuf, ISO7816.OFFSET_CDATA, (short) (lenA + pad));
        apdubuf[ISO7816.OFFSET_P1] = (byte) lenA;
        apdubuf[ISO7816.OFFSET_LC] = (byte) (lenA + pad);
        
        //need to pad ramArray1 from the left with 0s.
        Util.arrayCopyNonAtomic(m_ramArray1, SZERO, m_ramArray1, (short) (DH_GENERATOR_LENGTH - lenB), lenB);
        Util.arrayFillNonAtomic(m_ramArray1, SZERO, (short) (DH_GENERATOR_LENGTH - lenB - 1), BZERO);
        
        //(RSA) compute Primary Session Key
        //TUTO TO PADA
        try {
            lenA = m_DHCipher.doFinal(m_ramArray1, SZERO, DH_GENERATOR_LENGTH, m_ramArray2, SZERO);
        } catch (CryptoException e) {
            short reason = e.getReason();
            reason = e.getReason();
        }
        
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
        
        //send APDU with encrypted A (dataLen should be equal to RANDOM_LENGTH, but still)
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, RANDOM_LENGTH);
    }
    
    /**
     * Method checks PIN and Secure Channel
     * @param apdu encrypted by Session Key: receive A, send B
     */
    void CheckChannel(APDU apdu) {
        byte[]  apdubuf = apdu.getBuffer();
        short   dataLen = apdu.setIncomingAndReceive();

        
        //if (m_pin.check(apdubuf, ISO7816.OFFSET_CDATA, ISO7816.OFFSET_P1) == false) {
        //ISOException.throwIt(SW_BAD_PIN);
        //} else {
        //}
    }

    void EncryptFileKey(APDU apdu) {
        byte[]  apdubuf = apdu.getBuffer();
        short   dataLen = apdu.setIncomingAndReceive();
        
        
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 0); //INSERT MESSAGE LENGTH HERE);
    }
    
    void DecryptFileKey(APDU apdu) {
        byte[]  apdubuf = apdu.getBuffer();
        short   dataLen = apdu.setIncomingAndReceive();
        
        
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 0); //INSERT MESSAGE LENGTH HERE);
    }
    
    // SET PIN
    void SetPIN(APDU apdu) {
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();

        if (m_pin.isValidated()) {
            m_pin.update(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen);
        } else {
            ISOException.throwIt(SW_NEED_PIN);
        }
    }
}
