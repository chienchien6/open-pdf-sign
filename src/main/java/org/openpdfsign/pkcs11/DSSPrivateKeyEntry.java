package org.openpdfsign.pkcs11;

import java.security.cert.X509Certificate;

/**
 * Interface for private key entries.
 * This is a replacement for eu.europa.esig.dss.token.DSSPrivateKeyEntry
 * using IAIK PKCS#11 Wrapper.
 */
public interface DSSPrivateKeyEntry {
    
    /**
     * Gets the certificate associated with this key entry.
     * 
     * @return The certificate
     */
    X509Certificate getCertificate();
    
    /**
     * Gets the certificate chain associated with this key entry.
     * 
     * @return The certificate chain
     */
    X509Certificate[] getCertificateChain();
    
    /**
     * Gets the encryption algorithm used by this key entry.
     * 
     * @return The encryption algorithm
     */
    String getEncryptionAlgorithm();
    
    /**
     * Gets the alias of this key entry.
     * 
     * @return The alias
     */
    String getAlias();
}