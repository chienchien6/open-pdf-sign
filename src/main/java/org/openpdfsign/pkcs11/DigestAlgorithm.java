package org.openpdfsign.pkcs11;

import iaik.pkcs.pkcs11.Mechanism;

/**
 * Enumeration of supported digest algorithms for PKCS#11 operations.
 * This is a replacement for eu.europa.esig.dss.enumerations.DigestAlgorithm
 * using IAIK PKCS#11 Wrapper.
 */
public enum DigestAlgorithm {
    
    SHA1("SHA1", Mechanism.SHA_1),
    SHA256("SHA256", Mechanism.SHA256),
    SHA384("SHA384", Mechanism.SHA384),
    SHA512("SHA512", Mechanism.SHA512),
    MD5("MD5", Mechanism.MD5);
    
    private final String name;
    private final Mechanism mechanism;
    
    /**
     * Constructor for DigestAlgorithm.
     * 
     * @param name The name of the digest algorithm
     * @param mechanism The PKCS#11 mechanism for this algorithm
     */
    DigestAlgorithm(String name, Mechanism mechanism) {
        this.name = name;
        this.mechanism = mechanism;
    }
    
    /**
     * Gets the name of the digest algorithm.
     * 
     * @return The name of the digest algorithm
     */
    public String getName() {
        return name;
    }
    
    /**
     * Gets the PKCS#11 mechanism for this algorithm.
     * 
     * @return The PKCS#11 mechanism
     */
    public Mechanism getMechanism() {
        return mechanism;
    }
    
    /**
     * Gets a DigestAlgorithm by name.
     * 
     * @param name The name of the digest algorithm
     * @return The DigestAlgorithm or null if not found
     */
    public static DigestAlgorithm forName(String name) {
        if (name == null) {
            return null;
        }
        for (DigestAlgorithm algorithm : values()) {
            if (algorithm.name.equalsIgnoreCase(name)) {
                return algorithm;
            }
        }
        return null;
    }
}