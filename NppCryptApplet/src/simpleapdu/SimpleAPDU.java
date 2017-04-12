/*

TODO:
REFACTOR SIMPLEAPPLET -> NPPCRYPTAPPLET
CANGE APPLET IDs

*/

package simpleapdu;

import applets.NppCryptApplet;
import java.util.Arrays;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author xsvenda
 */
public class SimpleAPDU {
    static CardMngr cardManager = new CardMngr();

    private static byte DEFAULT_USER_PIN[] = {(byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30};
    private static byte NEW_USER_PIN[] = {(byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x31};
    private static byte APPLET_AID[] = {(byte) 0x73, (byte) 0x69, (byte) 0x6D, (byte) 0x70, (byte) 0x6C, 
        (byte) 0x65, (byte) 0x61, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    private static byte SELECT_NPPCRYPTAPPLET[] = {(byte) 0x00, (byte) 0xa4, (byte) 0x04, (byte) 0x00, (byte) 0x0b, 
        (byte) 0x73, (byte) 0x69, (byte) 0x6D, (byte) 0x70, (byte) 0x6C,
        (byte) 0x65, (byte) 0x61, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};

    private static final byte RNG_DATA[] = { (byte) 0xB0, (byte) 0x54, (byte) 0x10, (byte) 0x00, (byte) 0x00};
    
    public static void main(String[] args) {
        try {
            
            final boolean simulator = true;
                             
            // prepare 2 APDU commands
            
            //PIN validation
            short additionalDataLen = 0x04;
            byte apduPIN[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
            apduPIN[CardMngr.OFFSET_CLA] = (byte) 0xB0;
            apduPIN[CardMngr.OFFSET_INS] = (byte) 0x71;
            apduPIN[CardMngr.OFFSET_P1] = (byte) 0x00;
            apduPIN[CardMngr.OFFSET_P2] = (byte) 0x00;
            apduPIN[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
            apduPIN[CardMngr.OFFSET_DATA             ] = (byte) 0x03;
            apduPIN[CardMngr.OFFSET_DATA + (short)(1)] = (byte) 0x01;
            apduPIN[CardMngr.OFFSET_DATA + (short)(2)] = (byte) 0x07;
            apduPIN[CardMngr.OFFSET_DATA + (short)(3)] = (byte) 0x04;
            
            //HOTP Challenge
            additionalDataLen = 0x00;
            byte apdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
            apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
            apdu[CardMngr.OFFSET_INS] = (byte) 0x83;
            apdu[CardMngr.OFFSET_P1] = (byte) 0x00;
            apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
            apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
            //for (short i = 0; i < additionalDataLen; i++)
            //    apdu[CardMngr.OFFSET_DATA + i] = (byte) i;
           
            
            if (simulator) {
                
            // SIMULATED CARDS
            
            byte[] installData = new byte[] {(byte) 0x05, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                                             (byte) 0x01, (byte) 0x00, (byte) 0x14,
                                             (byte) 0x03, (byte) 0x01, (byte) 0x07, (byte) 0x04, //pin
                                             (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, //key
                                             (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                                             (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                                             (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff}; 
            
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, NppCryptApplet.class);            

            cardManager.sendAPDUSimulator(apduPIN);
            cardManager.sendAPDUSimulator(apdu);
 
            } else {

            // REAL CARDS
            
            if (cardManager.ConnectToCard()) {
                
                // Select our application on card
                cardManager.sendAPDU(SELECT_NPPCRYPTAPPLET);
                
                ResponseAPDU output;
                                
                //output = cardManager.sendAPDU(apdu);            //rejected, pin not validated
                //output = cardManager.sendAPDU(apduPIN);         //validate PIN (3174)
                output = cardManager.sendAPDU(apdu);            //send challenge and receive HOTP
                
                cardManager.DisconnectFromCard();
            } else {
                System.out.println("Failed to connect to card");
            }
            
            } //real cards

        } catch (Exception ex) {
            //System.out.println("Exception : " + ex);
            System.out.println("No card readers found.");
        }
    }
}
