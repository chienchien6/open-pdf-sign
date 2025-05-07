package org.openpdfsign.pkcs11;

import java.util.Arrays;

/**
 * Class representing a signature value.
 * This is a replacement for eu.europa.esig.dss.model.SignatureValue
 * using IAIK PKCS#11 Wrapper.
 */
public class SignatureValue {
    
    private DigestAlgorithm algorithm;
    private byte[] value;
    
    /**
     * Default constructor.
     */
    public SignatureValue() {
    }
    
    /**
     * Constructor with algorithm and value.
     * 
     * @param algorithm The digest algorithm used for signing
     * @param value The signature value bytes
     */
    public SignatureValue(DigestAlgorithm algorithm, byte[] value) {
        this.algorithm = algorithm;
        this.value = value;
    }
    
    /**
     * Gets the digest algorithm.
     * 
     * @return The digest algorithm
     */
    public DigestAlgorithm getAlgorithm() {
        return algorithm;
    }
    
    /**
     * Sets the digest algorithm.
     * 
     * @param algorithm The digest algorithm
     */
    public void setAlgorithm(DigestAlgorithm algorithm) {
        this.algorithm = algorithm;
    }
    
    /**
     * Gets the signature value bytes.
     * 
     * @return The signature value bytes
     */
    public byte[] getValue() {
        return value;
    }
    
    /**
     * Sets the signature value bytes.
     * 
     * @param value The signature value bytes
     */
    public void setValue(byte[] value) {
        this.value = value;
    }
    
    @Override
    public String toString() {
        return "SignatureValue[algorithm=" + algorithm + ", value=" + (value == null ? "null" : value.length + " bytes") + "]";
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SignatureValue that = (SignatureValue) o;
        return algorithm == that.algorithm && Arrays.equals(value, that.value);
    }
    
    @Override
    public int hashCode() {
        int result = algorithm != null ? algorithm.hashCode() : 0;
        result = 31 * result + Arrays.hashCode(value);
        return result;
    }
}