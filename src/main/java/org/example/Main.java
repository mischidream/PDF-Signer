package org.example;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.pades.signature.PAdESWithExternalCMSService;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.json.JSONObject;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;

import static org.junit.Assert.assertNotNull;

public class Main {
    private static final CertificateVerifier certificateVerifier = new CommonCertificateVerifier(); // Placeholder for cert verifier initialization

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("Usage:");
            System.out.println("  java -jar your.jar <signPDFDocument|signWithATrust> <input.pdf> <output.pdf>");
            return;
        }

        String mode = args[0];
        String inputPath = args[1];
        String outputPath = args[2];

        DSSDocument toSignDocument = new FileDocument(inputPath);

        switch (mode) {
            case "signDocument":
                signDocument(toSignDocument, outputPath);
                break;
            case "signWithATrust":
                signWithATrust(toSignDocument, outputPath);
                break;
            default:
                System.out.println("Unknown mode: " + mode);
                break;
        }
    }

    public static void signWithATrust(DSSDocument toSignDocument, String outputPath) throws Exception {
        String baseurl = "https://test.seal.a-trust.at/SealQualified/v1/";
        String pfxFile = "./src/main/java/org/example/0_Keys/authentication_certificate.p12";
        String pfxPassword = "testpwd";
        KeyStore keyStore = getKeyStore(pfxFile, pfxPassword.toCharArray());
        String keyAlias = getKeyAlias(keyStore);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, pfxPassword.toCharArray());
        String serial = getSerial(keyStore, keyAlias);
        X509Certificate sealCertificate = getSealCertificate(baseurl, serial);

        // Instantiate PDF signature service using external CMS
        PAdESWithExternalCMSService service = new PAdESWithExternalCMSService();
        ExternalCMSService externalCMSService = new ExternalCMSService(certificateVerifier);

        // Configure signature parameters
        PAdESSignatureParameters signatureParameters = setSignatureParameters();
        //signatureParameters.setGenerateTBSWithoutCertificate(true);

        assert sealCertificate != null;
        signatureParameters.setSigningCertificate(new CertificateToken(sealCertificate));
        signatureParameters.setCertificateChain(new CertificateToken(sealCertificate));

        // Prepare the PDF signature revision and compute message-digest of the byte range content
        // erst erstellen nach dem zertifikat damit es ecdsa
        DSSMessageDigest messageDigest = service.getMessageDigest(toSignDocument, signatureParameters);

        ToBeSigned dataToSign = externalCMSService.getDataToSign(messageDigest, signatureParameters);

        // Create hash of data to sign
        MessageDigest hashAlgo = MessageDigest.getInstance("SHA-256");
        byte[] hashToSign = hashAlgo.digest(dataToSign.getBytes());

        // Get signature value
        SignatureValue signValue = getSignatureValue(baseurl, privateKey, serial, hashToSign);
        //SignatureValue signValue = computeSignatureValueFromATrust(baseurl, serial, privateKey, dataToSign, signatureParameters.getDigestAlgorithm());

        // Sign the document with the external CMS
        DSSDocument cmsSignature = externalCMSService.signMessageDigest(messageDigest, signatureParameters, signValue);

        // Embed the obtained CMS signature to a PDF document with prepared signature revision
        DSSDocument signedDocument = service.signDocument(toSignDocument, signatureParameters, cmsSignature);
        signedDocument.save(outputPath);

        System.out.println("Signed successfully with A-Trust: " + outputPath);
    }

    public static void signDocument(DSSDocument toSignDocument, String outputPath) throws Exception {
        // Instantiate PDF signature service using external CMS
        PAdESWithExternalCMSService service = new PAdESWithExternalCMSService();

        // Configure signature parameters
        PAdESSignatureParameters signatureParameters = setSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());

        // Prepare the PDF signature revision and compute message-digest of the byte range content
        DSSMessageDigest messageDigest = service.getMessageDigest(toSignDocument, signatureParameters);
        assertNotNull(messageDigest);

        // Obtain CMS signature from external CMS signature provider
        DSSDocument cmsSignature = getExternalCMSSignature(messageDigest, signatureParameters, certificateVerifier);
        assertNotNull(cmsSignature);

        // Embed the obtained CMS signature to a PDF document with prepared signature revision
        DSSDocument signedDocument = service.signDocument(toSignDocument, signatureParameters, cmsSignature);
        signedDocument.save(outputPath);
        System.out.println("Signed successfully: " + outputPath);
    }

    public static PAdESSignatureParameters setSignatureParameters() {
        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setLocation("Vienna");
        signatureParameters.setReason("Certificate by X");
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.bLevel().setSigningDate(new Date());
        return signatureParameters;
    }

    public static KeyStore getKeyStore(String pfxFile, char[] pfxPassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        // Load PKCS12 keystore
        Security.setProperty("crypto.policy", "unlimited");
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        keystore.load(new FileInputStream(pfxFile), pfxPassword);
        return keystore;
    }

    public static String getKeyAlias(KeyStore keyStore) throws KeyStoreException {
        String keyAlias = "";
        for (Enumeration<?> en = keyStore.aliases(); en.hasMoreElements(); ) {
            String alias = (String) en.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                keyAlias = alias;
                break;
            }
        }
        return keyAlias;
    }

    public static String getSerial(KeyStore keyStore, String keyAlias) throws KeyStoreException {
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyAlias);
        return cert.getSerialNumber().toString();
    }

    public static SignatureValue getSignatureValue(String baseurl, PrivateKey key, String serial, byte[] hashToSign) throws Exception {
        String hashSignature = createHashSignature(key, hashToSign);
        String request = createSignRequest(serial, hashToSign, hashSignature);

        String postUrl = baseurl + "/Sign/nosessionid";
        String result = post(postUrl, request);

        // Extract and decode the signature value
        JSONObject obj = new JSONObject(result);
        String signature = obj.getString("Signature");

        return createDssCompatibleEcdsaSignature(signature.getBytes("UTF-8"));
    }

    public static String createHashSignature(PrivateKey key, byte[] hashToSign) throws Exception {
        Signature sig = Signature.getInstance("SHA256WithRSA");
        sig.initSign(key);
        sig.update(hashToSign);
        byte[] hashSignature = sig.sign();
        return Base64.getEncoder().encodeToString(hashSignature);
    }

    public static String createSignRequest(String serial, byte[] hashToSign, String hashSignature) {
        String hashed_data_b64 = new String(Base64.getEncoder().encode(hashToSign));
        return "{\"AuthSerial\": \"" + serial + "\", \"Hash\": \"" +
                hashed_data_b64 + "\", \"HashSignature\": \"" +
                hashSignature + "\", \"HashSignatureMechanism\": \"SHA256withRSA\" }";
    }

    public static X509Certificate getSealCertificate(String baseurl, String serial) {
        try {
            // Get seal certificate
            String getUrl = baseurl + "/Certificate/" + serial + "/nosessionid";
            byte[] sealCertificateRaw = get(getUrl);
            //byte[] sealCertificateRaw = getMocking(getUrl);

            String sealCertificateBase64 = new String(Base64.getEncoder().encode(sealCertificateRaw));

            // Convert byte array to X509Certificate
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(sealCertificateRaw));
        } catch (Exception e) {
            System.out.println("Get seal certificate exception: " + e);
        }
        return null;
    }

    public static String post(String postUrl, String requestJson) throws Exception {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httpPost = new HttpPost(postUrl);
        httpPost.setHeader("Accept", "application/json");
        httpPost.setHeader("Content-type", "application/json");
        httpPost.setEntity(new ByteArrayEntity(requestJson.getBytes("UTF8")));

        CloseableHttpResponse httpResponse = httpClient.execute(httpPost);
        String content = EntityUtils.toString(httpResponse.getEntity());
        httpClient.close();
        return content;
    }

    public static byte[] get(String getUrl) throws Exception {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpGet httpGet = new HttpGet(getUrl);
        CloseableHttpResponse httpResponse = httpClient.execute(httpGet);

        byte[] content = EntityUtils.toByteArray(httpResponse.getEntity());
        httpClient.close();
        return content;
    }

    public static SignatureValue createDssCompatibleEcdsaSignature(byte[] base64Signature) throws Exception {
        // Decode the signature from Base64
        byte[] rawSignature = Base64.getDecoder().decode(base64Signature);

        // Split the signature into R and S values
        int len = rawSignature.length / 2;
        BigInteger R = new BigInteger(1, Arrays.copyOfRange(rawSignature, 0, len));
        BigInteger S = new BigInteger(1, Arrays.copyOfRange(rawSignature, len, rawSignature.length));

        // Use BouncyCastle's ASN1 classes to encode R and S into a DER sequence
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(R));
        vector.add(new ASN1Integer(S));
        byte[] derEncodedSignature = new DERSequence(vector).getEncoded();

        // Return a SignatureValue compatible with DSS
        return new SignatureValue(SignatureAlgorithm.ECDSA_SHA256, derEncodedSignature);
    }

    public static DSSDocument getExternalCMSSignature(DSSMessageDigest messageDigest, PAdESSignatureParameters signatureParameters, CertificateVerifier certificateVerifier) throws Exception {
        // Instantiate CMS generation service for PAdES signature creation
        ExternalCMSService padesCMSGeneratorService = new ExternalCMSService(certificateVerifier);
        // Create DTBS (data to be signed) using the message-digest of a PDF signature byte range obtained from a client
        ToBeSigned dataToSign = padesCMSGeneratorService.getDataToSign(messageDigest, signatureParameters);
        // Sign the DTBS using a private key connection or remote-signing service
        SignatureValue signatureValue = computeSignatureValue(dataToSign, signatureParameters.getDigestAlgorithm());
        // Create a CMS signature using the provided message-digest, signature parameters and the signature value
        return padesCMSGeneratorService.signMessageDigest(messageDigest, signatureParameters, signatureValue);
    }

    public static CertificateToken getSigningCert() throws Exception {
        String pfxFile = "./src/main/java/org/example/0_Keys/cert.pfx";
        String pfxPassword = "test"; // The password for the PFX file
        // Load the PFX file and extract the certificate
        FileInputStream pfxInputStream = new FileInputStream(pfxFile);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(pfxInputStream, pfxPassword.toCharArray());
        // Extract certificate alias and get the certificate
        String alias = keyStore.aliases().nextElement();
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
        // Wrap in DSS CertificateToken
        return new CertificateToken(cert);
    }

    public static CertificateToken[] getCertificateChain() throws Exception {
        String pfxFile = "./src/main/java/org/example/0_Keys/cert.pfx";
        String pfxPassword = "test"; // The password for the PFX file
        // Load the PFX file and extract the certificate chain
        FileInputStream pfxInputStream = new FileInputStream(pfxFile);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(pfxInputStream, pfxPassword.toCharArray());
        // Extract the certificate chain
        String alias = keyStore.aliases().nextElement();
        Certificate[] certChain = keyStore.getCertificateChain(alias);
        // Convert to DSS CertificateToken[]
        CertificateToken[] certificateTokens = new CertificateToken[certChain.length];
        for (int i = 0; i < certChain.length; i++) {
            certificateTokens[i] = new CertificateToken((X509Certificate) certChain[i]);
        }
        return certificateTokens;
    }

    public static SignatureValue computeSignatureValue(ToBeSigned dataToSign, DigestAlgorithm digestAlgorithm) throws Exception {
        String pfxFile = "./src/main/java/org/example/0_Keys/cert.pfx";
        String pfxPassword = "test"; // The password for the PFX file
        // Load the PFX file and extract the private key
        FileInputStream pfxInputStream = new FileInputStream(pfxFile);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(pfxInputStream, pfxPassword.toCharArray());
        String alias = keyStore.aliases().nextElement();
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, pfxPassword.toCharArray());
        // Determine the appropriate signature algorithm based on the digest algorithm
        SignatureAlgorithm signatureAlgorithm = switch (digestAlgorithm) {
            case SHA256 -> SignatureAlgorithm.ECDSA_SHA256;
            case SHA512 -> SignatureAlgorithm.ECDSA_SHA512;
            // Add other cases as necessary (for example, for RSA algorithms)
            default -> throw new UnsupportedOperationException("Unsupported digest algorithm: " + digestAlgorithm);
        };
        // Initialize the signature with the private key and appropriate algorithm
        Signature signature = Signature.getInstance(signatureAlgorithm.getJCEId());
        signature.initSign(privateKey);
        signature.update(dataToSign.getBytes());
        // Compute the signature
        byte[] signedBytes = signature.sign();

        // Return the signature value with the appropriate algorithm
        return new SignatureValue(signatureAlgorithm, signedBytes);
    }
}