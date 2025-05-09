package org.openpdfsign.pkcs11;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import org.openpdfsign.SessionInitiator;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of SignatureTokenConnection for PKCS#11 tokens.
 * This class directly uses IAIK PKCS#11 Wrapper to interact with HSM.
 */
public class Pkcs11SignatureToken implements SignatureTokenConnection {

    private static final Logger log = Logger.getLogger(Pkcs11SignatureToken.class);

    private String pkcs11LibraryPath;
    private KeyStore.PasswordProtection passwordProtection;
    private int slotIndex;
    private Module pkcs11Module;
    private Session session;
    private List<DSSPrivateKeyEntry> keys = new ArrayList<>();

    /**
     * Constructor for Pkcs11SignatureToken.
     * 
     * @param pkcs11LibraryPath The path to the PKCS#11 library
     * @param passwordProtection The password protection for the token
     * @param slotIndex The slot index to use
     */
    public Pkcs11SignatureToken(String pkcs11LibraryPath, KeyStore.PasswordProtection passwordProtection, int slotIndex) {
        this.pkcs11LibraryPath = pkcs11LibraryPath;
        this.passwordProtection = passwordProtection;
        this.slotIndex = slotIndex;

        try {
            // Initialize the PKCS#11 module
            pkcs11Module = Module.getInstance(pkcs11LibraryPath);
            pkcs11Module.initialize(null);

            // Initialize the session
            char[] pin = passwordProtection.getPassword();
            session = SessionInitiator.defaultSessionInitiator().initiateSession(pkcs11Module, pin, slotIndex);

            if (session == null) {
                throw new IOException("Failed to initialize PKCS#11 session");
            }

            // Load all private keys
            PrivateKey keyTemplate = new PrivateKey();
            log.debug("Searching for private keys in HSM");
            session.findObjectsInit(keyTemplate);
            Object[] foundKeys = session.findObjects(100); // Find up to 100 keys
            session.findObjectsFinal();

            log.debug("Found " + foundKeys.length + " private keys in HSM");

            if (foundKeys.length == 0) {
                throw new IOException("No private keys found in the HSM");
            }

            // For each private key, find the corresponding certificate and create a DSSPrivateKeyEntry
            for (Object obj : foundKeys) {
                PrivateKey privateKey = (PrivateKey) obj;

                // Find the certificate with the same label as the key
                X509PublicKeyCertificate certTemplate = new X509PublicKeyCertificate();
                char[] keyLabel = privateKey.getLabel().getCharArrayValue();
                log.debug("Looking for certificate with label: " + new String(keyLabel));
                certTemplate.getLabel().setCharArrayValue(keyLabel);

                session.findObjectsInit(certTemplate);
                Object[] foundCerts = session.findObjects(1);
                session.findObjectsFinal();

                log.debug("Found " + foundCerts.length + " certificates with matching label");

                if (foundCerts.length > 0) {
                    X509PublicKeyCertificate pkcs11Cert = (X509PublicKeyCertificate) foundCerts[0];

                    // Convert PKCS#11 certificate to Java X509Certificate
                    X509Certificate[] certChain = convertToX509CertificateChain(pkcs11Cert);

                    // Create a DSSPrivateKeyEntry
                    IAIKPrivateKeyEntry entry = new IAIKPrivateKeyEntry(privateKey, pkcs11Cert, certChain);
                    keys.add(entry);
                    log.debug("Added key with alias: " + entry.getAlias());
                } else {
                    // Try to find any certificate if we couldn't find one with matching label
                    log.debug("No certificate found with matching label, trying to find any certificate");
                    X509PublicKeyCertificate anyCertTemplate = new X509PublicKeyCertificate();

                    session.findObjectsInit(anyCertTemplate);
                    Object[] anyFoundCerts = session.findObjects(1);
                    session.findObjectsFinal();

                    if (anyFoundCerts.length > 0) {
                        log.debug("Found a certificate without matching label");
                        X509PublicKeyCertificate pkcs11Cert = (X509PublicKeyCertificate) anyFoundCerts[0];

                        // Convert PKCS#11 certificate to Java X509Certificate
                        X509Certificate[] certChain = convertToX509CertificateChain(pkcs11Cert);

                        // Create a DSSPrivateKeyEntry
                        IAIKPrivateKeyEntry entry = new IAIKPrivateKeyEntry(privateKey, pkcs11Cert, certChain);
                        keys.add(entry);
                        log.debug("Added key with alias: " + entry.getAlias());
                    } else {
                        log.debug("No certificate found at all, skipping this key");
                    }
                }
            }
        } catch (TokenException | IOException | CertificateException e) {
            throw new RuntimeException("Failed to initialize PKCS#11 module or load keys: " + e.getMessage(), e);
        }
    }

    /**
     * Converts a PKCS#11 certificate to a Java X509Certificate chain.
     * 
     * @param pkcs11Cert The PKCS#11 certificate
     * @return The Java X509Certificate chain
     * @throws CertificateException If there is an error converting the certificate
     */
    private X509Certificate[] convertToX509CertificateChain(X509PublicKeyCertificate pkcs11Cert) throws CertificateException {
        byte[] certValue = pkcs11Cert.getValue().getByteArrayValue();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certValue));
        return new X509Certificate[] { cert };
    }

    @Override
    public List<DSSPrivateKeyEntry> getKeys() {
        return keys;
    }

    @Override
    public DSSPrivateKeyEntry getKey(String alias) {
        for (DSSPrivateKeyEntry key : keys) {
            if (alias.equals(key.getAlias())) {
                return key;
            }
        }
        return null;
    }

    @Override
    public SignatureValue sign(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm, DSSPrivateKeyEntry privateKey) {
        try {
            // Cast to IAIKPrivateKeyEntry to get access to the PKCS#11 private key
            IAIKPrivateKeyEntry iaikKey = (IAIKPrivateKeyEntry) privateKey;
            PrivateKey pkcs11Key = iaikKey.getPrivateKey();

            // Get the mechanism for signing
            iaik.pkcs.pkcs11.Mechanism signatureMechanism;
            String keyAlgo = iaikKey.getEncryptionAlgorithm().toUpperCase();

            if (keyAlgo.contains("EC") || keyAlgo.contains("ECDSA")) {
                // For ECDSA, the mechanism is just CKM_ECDSA. The hash is implied by the data to be signed.
                // Or, some HSMs might expect a combined mechanism if the library supports it directly.
                // We'll use CKM_ECDSA as it's more standard for raw ECDSA signing.
                // The actual hash (SHA1, SHA256, etc.) is part of the data to be signed, not the mechanism itself for CKM_ECDSA.
                signatureMechanism = iaik.pkcs.pkcs11.Mechanism.get(iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKM_ECDSA);
                log.debug("Using ECDSA mechanism: CKM_ECDSA");
            } else if (keyAlgo.contains("RSA")) {
                // For RSA, we combine the digest algorithm with RSA_PKCS
                // This is a common way to specify RSA with a specific hash
                if (digestAlgorithm == DigestAlgorithm.SHA1) {
                    signatureMechanism = iaik.pkcs.pkcs11.Mechanism.get(iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKM_SHA1_RSA_PKCS);
                    log.debug("Using RSA mechanism: CKM_SHA1_RSA_PKCS");
                } else if (digestAlgorithm == DigestAlgorithm.SHA256) {
                    signatureMechanism = iaik.pkcs.pkcs11.Mechanism.get(iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKM_SHA256_RSA_PKCS);
                    log.debug("Using RSA mechanism: CKM_SHA256_RSA_PKCS");
                } else if (digestAlgorithm == DigestAlgorithm.SHA384) {
                    signatureMechanism = iaik.pkcs.pkcs11.Mechanism.get(iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKM_SHA384_RSA_PKCS);
                    log.debug("Using RSA mechanism: CKM_SHA384_RSA_PKCS");
                } else if (digestAlgorithm == DigestAlgorithm.SHA512) {
                    signatureMechanism = iaik.pkcs.pkcs11.Mechanism.get(iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKM_SHA512_RSA_PKCS);
                    log.debug("Using RSA mechanism: CKM_SHA512_RSA_PKCS");
                } else {
                    // Fallback to generic RSA_PKCS if digest algorithm is not specifically handled
                    // This might not always work, depending on the HSM's expectations
                    signatureMechanism = iaik.pkcs.pkcs11.Mechanism.get(iaik.pkcs.pkcs11.wrapper.PKCS11Constants.CKM_RSA_PKCS);
                    log.warn("Using generic RSA_PKCS mechanism due to unhandled digest algorithm: " + digestAlgorithm.getName());
                }
            } else {
                log.error("Unsupported key algorithm for PKCS#11 signing: " + keyAlgo);
                throw new RuntimeException("Unsupported key algorithm for PKCS#11 signing: " + keyAlgo);
            }

            // Initialize the signing operation
            session.signInit(signatureMechanism, pkcs11Key);

            // Sign the data
            byte[] signatureBytes = session.sign(toBeSigned.getBytes());

            // Return the signature value
            return new SignatureValue(digestAlgorithm, signatureBytes);
        } catch (TokenException e) {
            throw new RuntimeException("Failed to sign data: " + e.getMessage(), e);
        }
    }

    @Override
    public void close() throws Exception {
        if (session != null) {
            try {
                session.closeSession();
            } catch (TokenException e) {
                throw new Exception("Failed to close PKCS#11 session: " + e.getMessage(), e);
            }
        }

        if (pkcs11Module != null) {
            try {
                pkcs11Module.finalize(null);
            } catch (TokenException e) {
                throw new Exception("Failed to finalize PKCS#11 module: " + e.getMessage(), e);
            }
        }
    }

    // Using the existing IAIKPrivateKeyEntry class instead of defining a nested class
}
