package org.openpdfsign.pkcs11;

import java.util.Arrays;

/**
 * Class representing data to be signed.
 * This is a replacement for eu.europa.esig.dss.model.ToBeSigned
 * using IAIK PKCS#11 Wrapper.
 */
public class ToBeSigned {
    
    private byte[] bytes;
    
    /**
     * Default constructor.
     */
    public ToBeSigned() {
    }
    
    /**
     * Constructor with bytes to be signed.
     * 
     * @param bytes The bytes to be signed
     */
    public ToBeSigned(byte[] bytes) {
        this.bytes = bytes;
    }
    
    /**
     * Gets the bytes to be signed.
     * 
     * @return The bytes to be signed
     */
    public byte[] getBytes() {
        return bytes;
    }
    
    /**
     * Sets the bytes to be signed.
     * 
     * @param bytes The bytes to be signed
     */
    public void setBytes(byte[] bytes) {
        this.bytes = bytes;
    }
    
    @Override
    public String toString() {
        return "ToBeSigned[bytes=" + (bytes == null ? "null" : bytes.length + " bytes") + "]";
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ToBeSigned that = (ToBeSigned) o;
        return Arrays.equals(bytes, that.bytes);
    }
    
    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }
}