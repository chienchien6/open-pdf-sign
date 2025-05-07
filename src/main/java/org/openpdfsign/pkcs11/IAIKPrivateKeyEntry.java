package org.openpdfsign.pkcs11;

import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import org.openpdfsign.pkcs11.DSSPrivateKeyEntry;

import java.security.cert.X509Certificate;

/**
 * Implementation of DSSPrivateKeyEntry that uses IAIKPKCS11Wrapper methods.
 * This class provides a bridge between the DSS library and IAIKPKCS11Wrapper.
 */
public class IAIKPrivateKeyEntry implements DSSPrivateKeyEntry {

    private PrivateKey privateKey;
    private X509PublicKeyCertificate certificate;
    private X509Certificate[] certificateChain;

    /**
     * Constructor for IAIKPrivateKeyEntry.
     * 
     * @param privateKey The PKCS#11 private key
     * @param certificate The PKCS#11 certificate
     * @param certificateChain The certificate chain
     */
    public IAIKPrivateKeyEntry(PrivateKey privateKey, X509PublicKeyCertificate certificate, X509Certificate[] certificateChain) {
        this.privateKey = privateKey;
        this.certificate = certificate;
        this.certificateChain = certificateChain;
    }

    @Override
    public X509Certificate getCertificate() {
        // In a real implementation, this would convert the PKCS#11 certificate to a Java X509Certificate
        return certificateChain[0];
    }

    @Override
    public X509Certificate[] getCertificateChain() {
        return certificateChain;
    }

    @Override
    public String getEncryptionAlgorithm() {
        // Return the encryption algorithm based on the key type
        return privateKey.getKeyType().toString();
    }

    @Override
    public String getAlias() {
        // Instead of using getAlias(), use the PKCS#11 key's label
        // This is the key change to replace key.getAlias() with IAIKPKCS11Wrapper methods
        return privateKey.getLabel().toString();
    }

    /**
     * Gets the PKCS#11 private key.
     * 
     * @return The PKCS#11 private key
     */
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Gets the PKCS#11 certificate.
     * 
     * @return The PKCS#11 certificate
     */
    public X509PublicKeyCertificate getPkcs11Certificate() {
        return certificate;
    }
}
