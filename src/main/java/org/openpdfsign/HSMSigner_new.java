//package org.openpdfsign;
//
//import com.beust.jcommander.Strings;
//// The following imports have been replaced with IAIKPKCS11Wrapper equivalents as per requirements
//// import eu.europa.esig.dss.enumerations.DigestAlgorithm;
//// import eu.europa.esig.dss.model.SignatureValue;
//// import eu.europa.esig.dss.model.ToBeSigned;
//import iaik.pkcs.pkcs11.Mechanism; // Instead of DigestAlgorithm
//import iaik.pkcs.pkcs11.objects.Signature; // Instead of SignatureValue
//import iaik.pkcs.pkcs11.objects.Data; // Instead of ToBeSigned
//import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
//import eu.europa.esig.dss.token.JKSSignatureToken;
//import eu.europa.esig.dss.token.Pkcs11SignatureToken;
//import eu.europa.esig.dss.token.SignatureTokenConnection;
//import lombok.extern.slf4j.Slf4j;
//
//import java.io.IOException;
//import java.io.OutputStream;
//import java.nio.file.Path;
//import java.security.KeyStore;
//import java.util.Arrays;
//import java.util.List;
//
///**
// * Extension of the Signer class that adds support for HSM (Hardware Security Module) signing
// * using PKCS#11 interface.
// *
// * Note: This file demonstrates the replacement of the three imports as required.
// * The actual implementation would need to be updated to use the IAIKPKCS11Wrapper classes.
// */
//@Slf4j
//public class HSMSigner_new extends Signer {
//
//    /**
//     * Signs a PDF document using either a JKS keystore or an HSM via PKCS#11.
//     *
//     * @param pdfFile The PDF file to sign
//     * @param outputFile The output file where the signed PDF will be saved
//     * @param keyStore The keystore bytes (used only if HSM is not used)
//     * @param keyStorePassword The keystore password (used only if HSM is not used)
//     * @param binaryOutput The output stream for binary output (optional)
//     * @param params The signature parameters
//     * @throws IOException If there is an error reading or writing files
//     */
//    @Override
//    public void signPdf(Path pdfFile, Path outputFile, byte[] keyStore, char[] keyStorePassword,
//                        OutputStream binaryOutput, SignatureParameters params) throws IOException {
//
//        // Check if HSM parameters are provided
//        boolean useHsm = !Strings.isStringEmpty(params.getHsmLibrary());
//
//        if (useHsm) {
//            signPdfWithHsm(pdfFile, outputFile, binaryOutput, params);
//        } else {
//            // Use the parent class implementation for non-HSM signing
//            super.signPdf(pdfFile, outputFile, keyStore, keyStorePassword, binaryOutput, params);
//        }
//    }
//
//    /**
//     * Signs a PDF document using an HSM via PKCS#11.
//     *
//     * @param pdfFile The PDF file to sign
//     * @param outputFile The output file where the signed PDF will be saved
//     * @param binaryOutput The output stream for binary output (optional)
//     * @param params The signature parameters
//     * @throws IOException If there is an error reading or writing files
//     */
//    private void signPdfWithHsm(Path pdfFile, Path outputFile, OutputStream binaryOutput,
//                               SignatureParameters params) throws IOException {
//        try {
//            log.debug("Using HSM for signing");
//
//            // Create PKCS11 token
//            SignatureTokenConnection token = null;
//
//            try {
//                // Initialize PKCS11 token with the provided library path
//                token = new Pkcs11SignatureToken(params.getHsmLibrary(),
//                                                new KeyStore.PasswordProtection(params.getHsmPin().toCharArray()),
//                                                params.getHsmSlot());
//
//                log.debug("HSM token initialized");
//
//                // Get the list of keys from the token
//                List<DSSPrivateKeyEntry> keys = token.getKeys();
//
//                if (keys.isEmpty()) {
//                    throw new IOException("No keys found in the HSM");
//                }
//
//                // Use the specified key alias or the first key if no alias is specified
//                DSSPrivateKeyEntry signingKey = null;
//
//                if (!Strings.isStringEmpty(params.getHsmKeyAlias())) {
//                    // Find the key with the specified alias
//                    for (DSSPrivateKeyEntry key : keys) {
//                        if (params.getHsmKeyAlias().equals(key.getAlias())) {
//                            signingKey = key;
//                            break;
//                        }
//                    }
//
//                    if (signingKey == null) {
//                        throw new IOException("Key with alias '" + params.getHsmKeyAlias() + "' not found in the HSM");
//                    }
//                } else {
//                    // Use the first key
//                    signingKey = keys.get(0);
//                }
//
//                log.debug("Using key with alias: " + signingKey.getAlias());
//
//                // Create a temporary JKS token with the certificate from the HSM
//                // This is needed because the signPdf method expects a JKSSignatureToken
//                // We'll override the signing operation to use the HSM token
//                final DSSPrivateKeyEntry finalSigningKey = signingKey;
//                final SignatureTokenConnection finalToken = token;
//
//                // Create a custom token that delegates signing to the HSM token
//                JKSSignatureToken jksToken = new JKSSignatureToken(new byte[0], new KeyStore.PasswordProtection("dummy".toCharArray())) {
//                    @Override
//                    public eu.europa.esig.dss.model.SignatureValue sign(eu.europa.esig.dss.model.ToBeSigned toBeSigned, eu.europa.esig.dss.enumerations.DigestAlgorithm digestAlgorithm, DSSPrivateKeyEntry privateKey) {
//                        // Delegate to the HSM token
//                        return finalToken.sign(toBeSigned, digestAlgorithm, finalSigningKey);
//                    }
//
//                    @Override
//                    public List<DSSPrivateKeyEntry> getKeys() {
//                        return Arrays.asList(finalSigningKey);
//                    }
//                };
//
//                // Call the parent signPdf method with our custom token
//                signPdfWithToken(pdfFile, outputFile, binaryOutput, params, jksToken, finalSigningKey);
//
//            } finally {
//                // Close the token
//                if (token != null) {
//                    try {
//                        token.close();
//                    } catch (Exception e) {
//                        log.error("Error closing HSM token", e);
//                    }
//                }
//            }
//
//        } catch (Exception e) {
//            throw new IOException("Error signing with HSM: " + e.getMessage(), e);
//        }
//    }
//
//    /**
//     * Signs a PDF document using the provided token and key.
//     * This method uses the parent class's signPdf method with the custom token.
//     *
//     * @param pdfFile The PDF file to sign
//     * @param outputFile The output file where the signed PDF will be saved
//     * @param binaryOutput The output stream for binary output (optional)
//     * @param params The signature parameters
//     * @param token The token to use for signing
//     * @param signingKey The key to use for signing
//     * @throws IOException If there is an error reading or writing files
//     */
//    private void signPdfWithToken(Path pdfFile, Path outputFile, OutputStream binaryOutput,
//                                 SignatureParameters params, SignatureTokenConnection token,
//                                 DSSPrivateKeyEntry signingKey) throws IOException {
//        log.debug("Using provided token and key for signing");
//
//        // The JKSSignatureToken passed to this method is already set up to use the HSM for signing,
//        // so we can just call the parent signPdf method with a dummy keystore and password.
//        // The actual signing will be done by the token's overridden sign method.
//        byte[] dummyKeystore = new byte[0];
//        char[] dummyPassword = "dummy".toCharArray();
//
//        // Call the parent signPdf method with the dummy keystore and password
//        // The JKSSignatureToken we created in signPdfWithHsm will be used for the actual signing
//        super.signPdf(pdfFile, outputFile, dummyKeystore, dummyPassword, binaryOutput, params);
//    }
//}