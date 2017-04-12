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
    final static byte INS_VERIFYPIN                 = (byte) 0x71;
    final static byte INS_SETPIN                    = (byte) 0x73;
    final static byte INS_GEN_HOTP                  = (byte) 0x81;
    final static byte INS_DUMP_EEPROM               = (byte) 0x83;
    final static byte INS_ENCRYPT_FILEKEY           = (byte) 0x85;
    final static byte INS_DECRYPT_FILEKEY           = (byte) 0x87;

    // CONSTANTS
    final static short ARRAY_LENGTH                 = (short) 0xff;
    final static short AES_BLOCK_LENGTH             = (short) 0x10;
    final static short CHALLENGE_LENGTH             = (short) 0x10;
    final static short HASH_LENGTH                  = (short) 0x14;
    
    // RESPONSES
    final static byte NEED_PIN[]                    =  {(byte) 0x50, (byte) 0x49, (byte) 0x4E};

    final static short SW_BAD_TEST_DATA_LEN         = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD            = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD    = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE      = (short) 0x6711;
    final static short SW_BAD_PIN                   = (short) 0x6900;
    final static short SW_CHALLENGE_LENGTH_BAD      = (short) 0x6969;

    private   AESKey         m_aesKey = null;
    private   RSAPrivateKey  m_rsaKey = null;
    private   MessageDigest  m_hash = null;
    private   OwnerPIN       m_pin = null;

    private   short          m_apduLogOffset = (short) 0;
    // TEMPORARY ARRAYS IN RAM
    private   byte        m_ramArray[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private   byte       m_dataArray[] = null;

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
            
            byte[] arrayPin = {(byte)0x03, (byte)0x01, (byte)0x07, (byte)0x04};
            byte[] arrayKey = {(byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                               (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                               (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 
                               (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff};
            Util.arrayCopyNonAtomic(arrayPin, (short) 0, m_dataArray, (short) 0, (short) 0x04);
            Util.arrayCopyNonAtomic(arrayKey, (short) 0, m_dataArray, (short) 4, (short) 0x10);
//            Util.arrayCopyNonAtomic(buffer, dataOffset, m_dataArray, (short) 0, buffer[(byte)(dataOffset - 1)]);
            
            // CREATE AES KEY OBJECT
            m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);

            // SET KEY VALUE
            m_aesKey.setKey(m_dataArray, (short) 4);

            //PIN, with tryLimit and maxPINsize
            m_pin = new OwnerPIN((byte) 5, (byte) 4);
            m_pin.update(m_dataArray, (byte) 0, (byte) 4);
            
            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);
            
            // Set EEPROM to 0s. No data needs to be stored in EEPROM,
            // since both PIN and Key are stored in their respective structures
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, length, (byte) 0);
            
            // INIT HASH ENGINE
            try {
                m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
            }
            catch (CryptoException e) {
               // HASH ENGINE NOT AVAILABLE
            }

            // update flag
            isOP2 = true;

        } else {
            //Nothing for now
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

    /**
     * Select method returns true if applet selection is supported.
     * @return boolean status of selection.
     */
    public boolean select()
    {
        // <PUT YOUR SELECTION ACTION HERE>
        
      return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect()
    {

        // <PUT YOUR DESELECTION ACTION HERE>

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
                case INS_VERIFYPIN: VerifyPIN(apdu); break;
                case INS_SETPIN: SetPIN(apdu); break;
                //case INS_GEN_HOTP: GenHOTP(apdu); break;
                case INS_DUMP_EEPROM: DumpEEPROM(apdu); break;
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

    //Test function to dump PIN and Key from eeprom via apdu
    void DumpEEPROM(APDU apdu) {
        byte[]  apdubuf = apdu.getBuffer();
        short   dataLen = apdu.setIncomingAndReceive();
        
        // copy data from EEPROM to apdu
        Util.arrayCopyNonAtomic(m_dataArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, HASH_LENGTH);
        
        // reeturn the value
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, HASH_LENGTH);
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
    /*
    // Recieve a challenge (128 bytes) and generate HOTP
    void GenHOTP(APDU apdu) {
        byte[]  apdubuf = apdu.getBuffer();
        short   dataLen = apdu.setIncomingAndReceive();
        
        //prepare buffers for message digests, load key from structure
        byte[]  ipad = new byte[(short) (CHALLENGE_LENGTH + dataLen)];
        byte[]  opad = new byte[(short) (CHALLENGE_LENGTH + HASH_LENGTH)];
        byte[]  key = new byte[AES_BLOCK_LENGTH];
        m_aesKey.getKey(key, (short) 0);
        
        // fill outer and inner paddings, XOR with 128 bit Key
        for (short i = 0; i < CHALLENGE_LENGTH; i++) {
            ipad[i] = (byte) (0x36 ^ key[i]);
            opad[i] = (byte) (0x5c ^ key[i]);
        }
        
        // append challenge to ipad
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, ipad, CHALLENGE_LENGTH, dataLen);
        
        // inner hash, stored in ramArray, 20 bytes written
        m_hash.doFinal(ipad, (short) 0, (short) (CHALLENGE_LENGTH + dataLen), m_ramArray, (short) 0);
        
        // append inner hash to outer pad
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, opad, CHALLENGE_LENGTH, HASH_LENGTH);
        
        // outer hash, stored in ramArray
        m_hash.doFinal(opad, (short) 0, (short) (CHALLENGE_LENGTH + HASH_LENGTH), m_ramArray, (short) 0);
        
        if (m_pin.isValidated()) {
            // copy hashed data back to apdu
            Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, HASH_LENGTH);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, HASH_LENGTH);
        } else {
            //If pin not validated, send back apdu with "PIN" message
            Util.arrayCopyNonAtomic(NEED_PIN, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) 3);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 3);
        }
    }
    */
    // VERIFY PIN
     void VerifyPIN(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      if (m_pin.check(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen) == false)
      ISOException.throwIt(SW_BAD_PIN);
    }

     // SET PIN
     void SetPIN(APDU apdu) {
      byte[]    apdubuf = apdu.getBuffer();
      short     dataLen = apdu.setIncomingAndReceive();

      if (m_pin.isValidated()) {
        m_pin.update(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen);
      } else {
        Util.arrayCopyNonAtomic(NEED_PIN, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, (short) 3);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 3);
      }
    }
}
