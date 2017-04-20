/*
 * PACKAGEID: 4C 61 62 61 6B
 * APPLETID: 4C 61 62 61 6B 41 70 70 6C 65 74
 */
package applets;

/*
 * Imported packages
 */
// specific import for Javacard API access
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class NppCryptApplet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_SIMPLEAPPLET              = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_BUILDCHANNEL              = (byte) 0x71;
    final static byte INS_CHECKCHANNEL              = (byte) 0x73;
    final static byte INS_SETPIN                    = (byte) 0x75;
    final static byte INS_GEN_HOTP                  = (byte) 0x81;
    final static byte INS_DUMP_EEPROM               = (byte) 0x83;
    final static byte INS_ENCRYPT_FILEKEY           = (byte) 0x85;
    final static byte INS_DECRYPT_FILEKEY           = (byte) 0x87;

    // CONSTANTS
    final static short ARRAY_LENGTH                 = (short) 0xff; //255 bytes
    final static short AES_BLOCK_LENGTH             = (short) 0x10; //16 bytes
    final static short CHALLENGE_LENGTH             = (short) 0x10; //16 bytes
    final static short HASH_LENGTH                  = (short) 0x14; //20 bytes
    final static short RANDOM_LENGTH                = (short) 0x80; //128 bytes
    final static short DH_GENERATOR_LENGTH          = (short) 0x80; //128 bytes
    final static short DH_MODULUS_LENGTH            = (short) 0x80; //128 bytes

    //these are public, no need to hide them
    final static byte DH_GENERATOR[]                = {};
    final static byte DH_MODULUS[]                  = {};

    final static short SZERO                        = (short) 0x0;
    final static byte  BZERO                        = (byte)  0x0;

    // APDU RESPONSES
    final static short SW_BAD_TEST_DATA_LEN         = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD            = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD    = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE      = (short) 0x6711;
    final static short SW_NEED_PIN                  = (short) 0x6922; 
    final static short SW_OK_PIN                    = (short) 0x6911;
    final static short SW_BAD_PIN                   = (short) 0x6900;
    final static short SW_CHALLENGE_LENGTH_BAD      = (short) 0x6969;

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

/////////////////////////////////////////////////////////////////////

    // INTERNAL STORAGE
    private   AESKey         m_KEK = null;          //this stores Key encryption key

    private   short      m_apduLogOffset = (short) 0;
    // TEMPORARY ARRAYS IN RAM
    private   byte       m_ramArray1[]    = null;
    private   byte       m_ramArray2[]    = null;
    // PERSISTENT ARRAY IN EEPROM
    private   byte       m_dataArray[]   = null;


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
            byte[] arrayKey = {(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                               (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                               (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                               (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff,
                               (byte)0xee, (byte)0xee, (byte)0xee, (byte)0xee}; //last 4 bytes are cut off
            Util.arrayCopyNonAtomic(arrayPin, (short) 0, m_dataArray, (short) 0, (short) 0x04);
            Util.arrayCopyNonAtomic(arrayKey, (short) 0, m_dataArray, (short) 4, (short) 0x10);
//            Util.arrayCopyNonAtomic(buffer, dataOffset, m_dataArray, (short) 0, buffer[(byte)(dataOffset - 1)]);
            
            // INITIALIZE RNG, RSA, KEY
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
            m_DHCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            m_DHKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_1024, false);
                    
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
            m_pin = new OwnerPIN((byte) 5, (byte) 8);
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
        new NppCryptApplet (bArray, bOffset, bLength);
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
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();

        //Generate exponent (not sure about the length, but 0x80 = 128 bytes = 1024 bits
        m_secureRandom.generateData(m_ramArray1, SZERO, RANDOM_LENGTH);
      
        //Compute A (Fill RSAKey with exponent, modulus, init cipher, encrypt)
        m_DHKey.setExponent(m_ramArray1, SZERO, RANDOM_LENGTH);
        m_DHKey.setModulus(DH_MODULUS, SZERO, DH_MODULUS_LENGTH);
        m_DHCipher.init(m_DHKey, Cipher.MODE_ENCRYPT);
        m_DHCipher.doFinal(DH_GENERATOR, SZERO, RANDOM_LENGTH, m_ramArray1, SZERO);

        //Encrypt A with preshared secret, store it in secondary ram array
        m_encryptCipher.doFinal(m_ramArray1, SZERO, RANDOM_LENGTH, m_ramArray2, SZERO);

        //Decrypt & copy B to RAM (from plugin to card)
        m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, RANDOM_LENGTH, m_ramArray1, SZERO);
        //Copy encrypted A to APDU (from card to plugin)
        Util.arrayCopyNonAtomic(m_ramArray2, SZERO, apdubuf, ISO7816.OFFSET_CDATA, RANDOM_LENGTH);

        //compute Session Key
        m_DHCipher.doFinal(m_ramArray1, SZERO, RANDOM_LENGTH, m_ramArray2, SZERO);
        //Init cipher with session Key
        
        //send APDU with encrypted A (dataLen should be equal to RANDOM_LENGTH, but still)
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, RANDOM_LENGTH);
        
        //apdubufSend = encrypted A
        //m_ramArray1 = plain B
        //m_ramArray2 = Session Key
        
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
