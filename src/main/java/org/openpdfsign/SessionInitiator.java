package org.openpdfsign;

import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.Module;

public class SessionInitiator {
    private static SessionInitiator sessionInitiator;

    private Slot[] slotsWithTokens = null;

    /**
     * Singleton pattern is used in here.
     * Get the default SessionInitiator.
     *
     * @return Instance of a SessionInitiator
     */
    public static SessionInitiator defaultSessionInitiator() {
        if (sessionInitiator == null) {
            sessionInitiator = new SessionInitiator();
        }
        return sessionInitiator;
    }


    private SessionInitiator() {
    }

    /**
     * Initiate a session.
     *
     * @param pkcs11Module : PKCS #11 module.
     * @param userPin      : User PIN of the slot.
     * @param slotNo       : Slot number of the required session
     * @return Instance of a Session.
     */
    public Session initiateSession(Module pkcs11Module, char[] userPin, int slotNo) {
        Session session = null;
        if (slotsWithTokens == null) {
            try {
                slotsWithTokens = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
                System.out.println("Found " + slotsWithTokens.length + " slots with tokens");
                for (int i = 0; i < slotsWithTokens.length; i++) {
                    System.out.println("Slot " + i + ": " + slotsWithTokens[i].getSlotID());
                }
            } catch (TokenException e) {
                System.out.println("Session initiation error when getting slot list: " + e.getMessage());
                e.printStackTrace();
                return null;
            }
        }
        
        if (slotsWithTokens.length == 0) {
            System.out.println("No slots with tokens found");
            return null;
        }
        
        if (slotNo >= slotsWithTokens.length) {
            System.out.println("Requested slot number " + slotNo + " is out of range. Only " + slotsWithTokens.length + " slots available.");
            return null;
        }
        
        Slot slot = slotsWithTokens[slotNo];
        System.out.println("Using slot " + slotNo + " with ID: " + slot.getSlotID());
        
        try {
            Token token = slot.getToken();
            try {
                TokenInfo tokenInfo = token.getTokenInfo();
                System.out.println("Token label: " + new String(tokenInfo.getLabel()).trim());
                System.out.println("Token Manufacturer ID: " + new String(tokenInfo.getManufacturerID()).trim());
                System.out.println("Token Model: " + new String(tokenInfo.getModel()).trim());
                System.out.println("Token Serial Number: " + new String(tokenInfo.getSerialNumber()).trim());
            } catch (TokenException te) {
                System.out.println("Error getting token info: " + te.getMessage());
                te.printStackTrace();
                // Optionally, rethrow or handle as critical error if token info is essential
            }
            
            session = token.openSession(Token.SessionType.SERIAL_SESSION,
                    Token.SessionReadWriteBehavior.RW_SESSION, null, null);
            System.out.println("Session opened successfully");
            
            session.login(Session.UserType.USER, userPin);
            System.out.println("Logged in successfully");
        } catch (TokenException e) {
            System.out.println("Session initiation error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
        return session;
    }
}