package org.openpdfsign.pkcs11;

import java.util.List;

/**
 * Interface for signature token connections.
 * This is a replacement for eu.europa.esig.dss.token.SignatureTokenConnection
 * using IAIK PKCS#11 Wrapper.
 */
public interface SignatureTokenConnection extends AutoCloseable {
    
    /**
     * Gets the list of keys available in this token.
     * 
     * @return The list of keys
     */
    List<DSSPrivateKeyEntry> getKeys();
    
    /**
     * Gets a key by its alias.
     * 
     * @param alias The alias of the key
     * @return The key entry
     */
    DSSPrivateKeyEntry getKey(String alias);
    
    /**
     * Signs data using the specified key and digest algorithm.
     * 
     * @param toBeSigned The data to be signed
     * @param digestAlgorithm The digest algorithm to use
     * @param privateKey The private key to use for signing
     * @return The signature value
     */
    SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, DSSPrivateKeyEntry privateKey);
    
    /**
     * Closes this token connection.
     */
    @Override
    void close() throws Exception;
}