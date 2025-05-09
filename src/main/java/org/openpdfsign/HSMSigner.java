package org.openpdfsign;

import com.beust.jcommander.Strings;
// Using IAIKPKCS11Wrapper equivalents as per requirements
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.tsp.CompositeTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import org.apache.commons.io.IOUtils;
import iaik.pkcs.pkcs11.Mechanism; // For DigestAlgorithm
import iaik.pkcs.pkcs11.objects.Data; // For ToBeSigned
// Using local implementations instead of eu.europa.esig.dss classes
import org.apache.commons.lang3.StringUtils;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.openpdfsign.pkcs11.*;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Extension of the Signer class that adds support for HSM (Hardware Security Module) signing
 * using PKCS#11 interface.
 * 
 * This implementation uses a PKCS#11 token for signing operations, but creates a JKS token wrapper
 * to make it compatible with the parent Signer class which expects a JKSSignatureToken.
 * The JKS token wrapper delegates the actual signing operation to the PKCS#11 token.
 */
public class HSMSigner extends Signer {

    private static final Logger log = Logger.getLogger(HSMSigner.class);

    /**
     * Signs a PDF document using either a JKS keystore or an HSM via PKCS#11.
     * 
     * @param pdfFile The PDF file to sign
     * @param outputFile The output file where the signed PDF will be saved
     * @param keyStore The keystore bytes (used only if HSM is not used)
     * @param keyStorePassword The keystore password (used only if HSM is not used)
     * @param binaryOutput The output stream for binary output (optional)
     * @param params The signature parameters
     * @throws IOException If there is an error reading or writing files
     */
    @Override
    public void signPdf(Path pdfFile, Path outputFile, byte[] keyStore,
                        char[] keyStorePassword, OutputStream binaryOutput,
                        SignatureParameters params) throws IOException {
        if (!Strings.isStringEmpty(params.getHsmLibrary())) {
            signPdfWithHsm(pdfFile, outputFile, binaryOutput, params);
        } else {
            super.signPdf(pdfFile, outputFile, keyStore, keyStorePassword,
                    binaryOutput, params);
        }
    }



    private void signPdfWithHsm(Path pdfFile, Path outputFile,
                                OutputStream binaryOutput,
                                SignatureParameters params) throws IOException {
        SignatureTokenConnection token = null;
        try {
            // 创建PKCS11令牌
            token = new Pkcs11SignatureToken(
                    params.getHsmLibrary(),
                    new KeyStore.PasswordProtection(params.getHsmPin().toCharArray()),
                    params.getHsmSlot()
            );

            // 获取密钥
            List<DSSPrivateKeyEntry> keys = token.getKeys();
            if (keys.isEmpty()) {
                throw new IOException("No keys found in HSM");
            }

            // 选择签名密钥
            DSSPrivateKeyEntry signingKey = selectSigningKey(keys, params.getHsmKeyAlias());

            // 直接使用token进行签名
            signPdfWithToken(pdfFile, outputFile, binaryOutput, params, token, signingKey);

        } finally {
            if (token != null) {
                try {
                    token.close();
                } catch (Exception e) {
                    log.error("Error closing HSM token", e);
                }
            }
        }
    }

    /**
 * Creates a CommonCertificateVerifier based on the signature parameters.
 * @param signatureParameters The PAdES signature parameters.
 * @return Configured CommonCertificateVerifier instance.
 */
private CommonCertificateVerifier createCertificateVerifier(PAdESSignatureParameters signatureParameters) {
    CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();

    // Check signature level using reflection
    SignatureLevel level = null;
    try {
        level = (SignatureLevel) signatureParameters.getClass().getMethod("getSignatureLevel").invoke(signatureParameters);
    } catch (Exception e) {
        log.error("Error getting signature level: " + e.getMessage(), e);
        // Default to LT level to ensure we set up the verifier properly
        level = SignatureLevel.PAdES_BASELINE_LT;
    }

    if (level == SignatureLevel.PAdES_BASELINE_LT ||
            level == SignatureLevel.PAdES_BASELINE_LTA) {
        // Capability to download resources from AIA
        commonCertificateVerifier.setAIASource(new DefaultAIASource());

        // Capability to request OCSP Responders
        commonCertificateVerifier.setOcspSource(new OnlineOCSPSource());

        // Capability to download CRL
        commonCertificateVerifier.setCrlSource(new OnlineCRLSource());

        // Still fetch revocation data for signing, even if a certificate chain is not trusted
        commonCertificateVerifier.setCheckRevocationForUntrustedChains(true);

        // Create an instance of a trusted certificate source
        CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();

        // Import defaults or custom certificates if needed
        CommonCertificateSource commonCertificateSource = new CommonCertificateSource();
        trustedCertSource.importAsTrusted(commonCertificateSource);

        commonCertificateVerifier.addTrustedCertSources(trustedCertSource);
    }
    return commonCertificateVerifier;
}

    private DSSPrivateKeyEntry selectSigningKey(List<DSSPrivateKeyEntry> keys,
                                                String alias) throws IOException {
        if (Strings.isStringEmpty(alias)) {
            return keys.get(0);
        }
        return keys.stream()
                .filter(key -> alias.equals(key.getAlias()))
                .findFirst()
                .orElseThrow(() -> new IOException(
                        "Key with alias '" + alias + "' not found in HSM"
                ));
    }
    /**
     * Signs a PDF document using the provided token and key.
     * This method uses the parent class's signPdf method with the custom token.
     * 
     * @param pdfFile The PDF file to sign
     * @param outputFile The output file where the signed PDF will be saved
     * @param binaryOutput The output stream for binary output (optional)
     * @param params The signature parameters
     * @param token The token to use for signing
     * @param signingKey The key to use for signing
     * @throws IOException If there is an error reading or writing files
     */

    protected void signPdfWithToken(Path pdfFile, Path outputFile,
                                    OutputStream binaryOutput,
                                    SignatureParameters params,
                                    SignatureTokenConnection token,
                                    DSSPrivateKeyEntry signingKey) throws IOException {
        try {
            DSSDocument toSignDocument = new FileDocument(pdfFile.toFile());

            // 创建签名参数
            PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();

            // Convert X509Certificate to CertificateToken and set it
            X509Certificate cert = signingKey.getCertificate();
            CertificateToken certToken = new CertificateToken(cert);
            // Use reflection to call setSigningCertificate
            try {
                signatureParameters.getClass().getMethod("setSigningCertificate", CertificateToken.class)
                    .invoke(signatureParameters, certToken);
            } catch (Exception e) {
                throw new IOException("Error setting signing certificate: " + e.getMessage(), e);
            }

            // Convert X509Certificate[] to List<CertificateToken> and set it
            X509Certificate[] certChain = signingKey.getCertificateChain();
            List<CertificateToken> certTokenChain = new ArrayList<>();
            for (X509Certificate chainCert : certChain) {
                certTokenChain.add(new CertificateToken(chainCert));
            }
            // Use reflection to call setCertificateChain
            try {
                signatureParameters.getClass().getMethod("setCertificateChain", List.class)
                    .invoke(signatureParameters, certTokenChain);
            } catch (Exception e) {
                throw new IOException("Error setting certificate chain: " + e.getMessage(), e);
            }

            // 配置签名参数
            configureSignatureParameters(signatureParameters, params);

            // 设置代理（如果需要）
            ProxyConfig proxyConfig = this.retrieveProxyConfig();

            // 创建验证器
            CommonCertificateVerifier commonCertificateVerifier = createCertificateVerifier(signatureParameters);

            // 创建签名服务
            PAdESService service = new PAdESService(commonCertificateVerifier);

            // 配置可视签名（如果需要）
            if (params.getPage() != null) {
                // Implement visible signature configuration inline instead of calling a separate method
                SignatureImageParameters imageParameters = new SignatureImageParameters();
                TableSignatureFieldParameters fieldParameters = new TableSignatureFieldParameters();
                imageParameters.setFieldParameters(fieldParameters);

                try {
                    if (!Strings.isStringEmpty(params.getImageFile())) {
                        imageParameters.setImage(new InMemoryDocument(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(params.getImageFile()))));
                    } else {
                        imageParameters.setImage(new InMemoryDocument(IOUtils.toByteArray(getClass().getClassLoader().getResourceAsStream("signature.png"))));
                    }

                    fieldParameters.setPage(params.getPage());
                    fieldParameters.setOriginX(params.getLeft() * 7.2f); // Convert mm to points
                    fieldParameters.setOriginY(params.getTop() * 7.2f);
                    fieldParameters.setWidth(params.getWidth() * 7.2f);

                    signatureParameters.setImageParameters(imageParameters);
                } catch (Exception e) {
                    log.error("Error configuring visible signature: " + e.getMessage(), e);
                }
            }

            // 配置时间戳（如果需要）
            if (params.getUseTimestamp() || params.getUseLT() || params.getUseLTA() || !params.getTSA().isEmpty()) {
                CompositeTSPSource compositeTSPSource = new CompositeTSPSource();
                Map<String, TSPSource> tspSources = new HashMap<>();
                compositeTSPSource.setTspSources(tspSources);

                if (params.getTSA().isEmpty()) {
                    // Use default TSP sources if none specified
                    tspSources.put("http://timestamp.digicert.com", buildTspSource("http://timestamp.digicert.com", proxyConfig));
                } else {
                    for (String source : params.getTSA()) {
                        tspSources.put(source, buildTspSource(source, proxyConfig));
                    }
                }

                service.setTspSource(compositeTSPSource);
            }

            // 设置PDF密码（如果需要）
            if (!StringUtils.isEmpty(params.getPdfPassphrase())) {
                signatureParameters.setPasswordProtection(params.getPdfPassphrase().toCharArray());
            }

            // 获取要签名的数据
            eu.europa.esig.dss.model.ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);

            // Convert EU DSS ToBeSigned to custom ToBeSigned
            org.openpdfsign.pkcs11.ToBeSigned customToBeSigned = new org.openpdfsign.pkcs11.ToBeSigned(dataToSign.getBytes());

            // Convert EU DSS DigestAlgorithm to custom DigestAlgorithm
            eu.europa.esig.dss.enumerations.DigestAlgorithm euDigestAlgorithm = signatureParameters.getDigestAlgorithm();
            org.openpdfsign.pkcs11.DigestAlgorithm customDigestAlgorithm = convertDigestAlgorithm(euDigestAlgorithm);

            // 使用token进行签名
            org.openpdfsign.pkcs11.SignatureValue customSignatureValue = token.sign(customToBeSigned, customDigestAlgorithm, signingKey);

            // Determine EncryptionAlgorithm based on the key type
            String keyAlgorithmString = signingKey.getEncryptionAlgorithm();
            EncryptionAlgorithm encryptionAlgorithm;
            if (keyAlgorithmString != null && (keyAlgorithmString.toUpperCase().contains("EC") || keyAlgorithmString.toUpperCase().contains("ECDSA"))) {
                encryptionAlgorithm = EncryptionAlgorithm.ECDSA;
                log.debug("Determined encryption algorithm: ECDSA for key type: " + keyAlgorithmString);
            } else if (keyAlgorithmString != null && keyAlgorithmString.toUpperCase().contains("RSA")) {
                encryptionAlgorithm = EncryptionAlgorithm.RSA;
                log.debug("Determined encryption algorithm: RSA for key type: " + keyAlgorithmString);
            } else {
                log.warn("Unknown or null key algorithm: " + keyAlgorithmString + ". Defaulting to RSA. This might cause issues.");
                encryptionAlgorithm = EncryptionAlgorithm.RSA; // Defaulting to RSA as a fallback
            }

            // Create EU DSS SignatureValue using the determined encryption algorithm
            SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, euDigestAlgorithm);
            eu.europa.esig.dss.model.SignatureValue euSignatureValue = new eu.europa.esig.dss.model.SignatureValue(signatureAlgorithm, customSignatureValue.getValue());

            // 完成文档签名
            DSSDocument signedDocument = service.signDocument(toSignDocument, signatureParameters, euSignatureValue);

            // 保存签名后的文档
            if (binaryOutput != null) {
                signedDocument.writeTo(binaryOutput);
            } else {
                signedDocument.save(outputFile.toAbsolutePath().toString());
            }

        } catch (Exception e) {
            throw new IOException("Error signing PDF: " + e.getMessage(), e);
        }
    }

    /**
     * Converts EU DSS DigestAlgorithm to custom DigestAlgorithm
     */
    private org.openpdfsign.pkcs11.DigestAlgorithm convertDigestAlgorithm(eu.europa.esig.dss.enumerations.DigestAlgorithm euAlgorithm) {
        switch (euAlgorithm.getName()) {
            case "SHA1":
                return org.openpdfsign.pkcs11.DigestAlgorithm.SHA1;
            case "SHA256":
                return org.openpdfsign.pkcs11.DigestAlgorithm.SHA256;
            case "SHA384":
                return org.openpdfsign.pkcs11.DigestAlgorithm.SHA384;
            case "SHA512":
                return org.openpdfsign.pkcs11.DigestAlgorithm.SHA512;
            default:
                return org.openpdfsign.pkcs11.DigestAlgorithm.SHA256; // Default
        }
    }

    /**
     * Creates a TSP source for the given URL
     */
    private OnlineTSPSource buildTspSource(String source, ProxyConfig proxyConfig) {
        TimestampDataLoader timestampDataLoader = new TimestampDataLoader();
        timestampDataLoader.setProxyConfig(proxyConfig);
        return new OnlineTSPSource(source, timestampDataLoader);
    }

    // 添加一些必要的辅助方法来分解原始signPdf方法的功能
    private void configureSignatureParameters(PAdESSignatureParameters signatureParameters,
                                              SignatureParameters params) {
        // 从原始signPdf方法中提取签名参数配置逻辑
        if (params.getUseLT()) {
            signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
            signatureParameters.setContentSize((int) (SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2.5)); // Increased from 1.5 to 2.5
        } else if (params.getUseLTA()) {
            signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
            signatureParameters.setContentSize((int) (SignatureOptions.DEFAULT_SIGNATURE_SIZE * 3.0)); // Increased from 1.75 to 3.0
        } else if (params.getUseTimestamp() || !params.getTSA().isEmpty()) {
            signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
            signatureParameters.setContentSize((int) (SignatureOptions.DEFAULT_SIGNATURE_SIZE * 1.5));
        } else {
            signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        }

        // 设置其他参数
        if (!Strings.isStringEmpty(params.getLocation())) {
            signatureParameters.setLocation(params.getLocation());
        }
        if (!Strings.isStringEmpty(params.getReason())) {
            signatureParameters.setReason(params.getReason());
        }
        if (!Strings.isStringEmpty(params.getContact())) {
            signatureParameters.setContactInfo(params.getContact());
        }
        signatureParameters.setAppName("open-pdf-sign");
    }
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
//
//    protected void signPdfWithToken(Path pdfFile, Path outputFile,
//                                    OutputStream binaryOutput,
//                                    SignatureParameters params,
//                                    SignatureTokenConnection token,
//                                    DSSPrivateKeyEntry signingKey) throws IOException {
//        try {
//            // 加载PDF文档
//            DSSDocument toSignDocument = new FileDocument(pdfFile.toFile());
//
//            // 创建签名参数
//            PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
//            signatureParameters.setSigningCertificate(signingKey.getCertificate());
//            signatureParameters.setCertificateChain(signingKey.getCertificateChain());
//
//            // 设置签名级别和其他参数
//            configureSignatureParameters(signatureParameters, params);
//
//            // 创建签名服务
//            PAdESService service = createPAdESService(params);
//
//            // 获取要签名的数据
//            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, signatureParameters);
//
//            // 使用token进行签名
//            SignatureValue signatureValue = token.sign(dataToSign,
//                    signatureParameters.getDigestAlgorithm(),
//                    signingKey);
//
//            // 完成签名并保存文档
//            DSSDocument signedDocument = service.signDocument(toSignDocument,
//                    signatureParameters,
//                    signatureValue);
//
//            if (binaryOutput != null) {
//                signedDocument.writeTo(binaryOutput);
//            } else {
//                signedDocument.save(outputFile.toAbsolutePath().toString());
//            }
//
//        } catch (Exception e) {
//            throw new IOException("Error signing PDF: " + e.getMessage(), e);
//        }
//    }

}
