package cryptography;


import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;


import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;

import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class Certfile {

    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String keystoreFileLocation="src" + File.separator  + "userPKCS12Cert";
    private static final String numberOfLoginLocation="src" + File.separator + "numberOfLogin.txt";

    public static String getKeystoreFileLocation(){return keystoreFileLocation;}

    public static X509Certificate x509ReqToX509(PKCS10CertificationRequest csr, int days, PrivateKey caKey, X509Certificate caCert) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, CertificateEncodingException, SignatureException {
        Date notBefore = new Date();
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DATE, days);
        Date notAfter = cal.getTime();

        BigInteger serialNumber = new BigInteger(32,new Random());

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        KeyUsage keyUsage=new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment);
        certGen.addExtension(Extension.keyUsage,false,keyUsage);
        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(caCert.getSubjectX500Principal());
        certGen.setSubjectDN(X509Name.getInstance(csr.getCertificationRequestInfo().getSubject()));
        certGen.setNotBefore(notBefore);
        certGen.setNotAfter(notAfter);
        certGen.setPublicKey(csr.getPublicKey());
        certGen.setSignatureAlgorithm(SIGNATURE_ALGORITHM);

        return certGen.generate(caKey, BC_PROVIDER);
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(4096, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }
    public static MyRequest createCSR(final String commonName) throws GeneralSecurityException {

        KeyPair keyPair = generateKeyPair();
        final String signatureAlgorithm = SIGNATURE_ALGORITHM;
        final X500Principal principal = new X500Principal("CN=" + commonName + ", O=Elektrotehnicki fakultet, OU= ETF, L=Banja Luka, ST=RS, C=BA");


        DERSequence sanExtension= new DERSequence(new ASN1Encodable[] {
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyAgreement)
        });
        DERSet extensions = new DERSet(new DERSequence(sanExtension));
        DERSequence extensionRequest = new DERSequence(new ASN1Encodable[] {
                PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                extensions
        });
        DERSet attributes = new DERSet(extensionRequest);
        return new MyRequest(new PKCS10CertificationRequest(
                signatureAlgorithm,
                principal,
                keyPair.getPublic(),
                attributes,
                keyPair.getPrivate()),keyPair);
    }


    public static void exportKeyPairToKeystoreFile(KeyPair keyPair, X509Certificate certificate, String alias, String fileName,String storePass ) throws Exception {

        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        keyStore.load(null, null);

        ArrayList<X509Certificate> certificateArrayList=new ArrayList<>();
         certificateArrayList.add(certificate);

        keyStore.setKeyEntry(alias, keyPair.getPrivate(), storePass.toCharArray(),
                certificateArrayList.toArray(new Certificate[certificateArrayList.size()]));
        FileOutputStream fOut = new FileOutputStream(keystoreFileLocation + File.separator + fileName + ".p12");
        keyStore.store(fOut, storePass.toCharArray());

    }


    public static String certToString(X509Certificate cert) throws IOException {
        StringWriter sw = new StringWriter();

        return sw.toString();

}
    public static String x509ToPemFile(X509Certificate certificate)
            throws CertificateEncodingException
    {
        Base64 encoder = new Base64();
        String cert_begin = "-----BEGIN CERTIFICATE-----\n";
        String end_cert = "-----END CERTIFICATE-----";
        byte[] derCert = certificate.getEncoded();
        String pemCertPre = new String(encoder.encode(derCert));
        String pemCert = cert_begin + pemCertPre + end_cert;
        return pemCert;
    }

    public static void writePemCertToFile(X509Certificate certificate, String userName) throws CertificateEncodingException, IOException {
        FileWriter fw = new FileWriter("src" + File.separator + "userCerts" + File.separator + userName + ".cer");
        fw.write(x509ToPemFile(certificate));
        fw.close();
    }


    public static X509Certificate readCertFromFile(String caName) throws CertificateException, FileNotFoundException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        FileInputStream is = new FileInputStream("src" + File.separator + "CACerts" + File.separator + caName);

        X509Certificate x509Certificate = (X509Certificate) certFactory.generateCertificate(is);
        return x509Certificate;
    }

    public static PrivateKey readPrivateKeyFromFile(String fileName) throws Exception {

        File f = new File("src" + File.separator + "CAKeys" + File.separator + fileName);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        String temp = new String(keyBytes);

        String privKeyPEM = temp.replace("-----BEGIN RSA PRIVATE KEY-----\n", "");
        privKeyPEM = privKeyPEM.replace("-----END RSA PRIVATE KEY-----", "");


        Base64 b64 = new Base64();
        byte [] decoded = b64.decode(privKeyPEM);


        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);

}

    public static void isKeyStorePass(String keyStore, String storePass) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {



            File file = new File(keystoreFileLocation + File.separator + keyStore);
            InputStream stream = new FileInputStream(file);
            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(stream, storePass.toCharArray());


    }

    public static void writeUserToLoginFile(String certName, String numberOfLogin)
            throws IOException {

        BufferedWriter bufferedWriter= new BufferedWriter(new FileWriter(numberOfLoginLocation,true));
        String string = certName + ".p12" + "#" + numberOfLogin;
        bufferedWriter.append(string);
        bufferedWriter.newLine();
        bufferedWriter.flush();
        bufferedWriter.close();


    }

    public static void deleteFileOnSomePath(String path){
        File file=new File(path);
        boolean b=file.delete();
    }

    public static String getCAName(String keyStore, String storePass) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {



        File file = new File(keystoreFileLocation + File.separator + keyStore);
        InputStream stream = new FileInputStream(file);
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(stream, storePass.toCharArray());
        String alias=keyStore.substring(0,keyStore.indexOf("."));
        Certificate certificate = store.getCertificate(alias);
        X509Certificate x509Certificate = (X509Certificate) certificate;

        X500Principal principal = new X500Principal(x509Certificate.getIssuerX500Principal().toString());
        return principal.getName();


    }


    public static X509CRL readCRLFromFile(String caName) throws CertificateException, FileNotFoundException, CRLException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        FileInputStream is = new FileInputStream("src" + File.separator + "CRLLists" + File.separator + caName + "crl.pem");

        X509CRL x509CRL= (X509CRL) certFactory.generateCRL(is);
        return x509CRL;
    }
    public static X509CRL createCRL(X509CRL oldCRL,X509Certificate caCert, PrivateKey caKey, BigInteger serialNumber) throws Exception {
        X509V2CRLGenerator crlGen = new X509V2CRLGenerator();
        Date now = new Date();
        crlGen.setIssuerDN(caCert.getSubjectX500Principal());
        crlGen.setThisUpdate(now);
        crlGen.setNextUpdate(new Date(now.getTime() + 100000));
        crlGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        Set<X509CRLEntry> revokeCerts=(Set<X509CRLEntry>) oldCRL.getRevokedCertificates();
        if(revokeCerts != null){
            for (Iterator<X509CRLEntry> iterator = revokeCerts.iterator(); iterator.hasNext();){
                X509CRLEntry x509CRLEntry=iterator.next();
                crlGen.addCRLEntry(x509CRLEntry.getSerialNumber(),x509CRLEntry.getRevocationDate(),CRLReason.cessationOfOperation);
            }

        }

        crlGen.addCRLEntry(serialNumber, now, CRLReason.cessationOfOperation);
        crlGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
        crlGen.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));

        return crlGen.generate(caKey, "BC");
    }

    public static BigInteger getSerialNumber(String keyStore, String storePass) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {



        File file = new File(keystoreFileLocation + File.separator + keyStore);
        InputStream stream = new FileInputStream(file);
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(stream, storePass.toCharArray());
        String alias=keyStore.substring(0,keyStore.indexOf("."));
        Certificate certificate = store.getCertificate(alias);
        X509Certificate x509Certificate = (X509Certificate) certificate;
        return x509Certificate.getSerialNumber();


    }

    public static String x509CRLToPemFile(X509CRL x509CRL)
            throws  CRLException {
        Base64 encoder = new Base64();
        String cert_begin = "-----BEGIN X509 CRL-----\n";
        String end_cert = "-----END X509 CRL-----";

        byte[] derCRL = x509CRL.getEncoded();
        String crlPre = new String(encoder.encode(derCRL));
        String crlPem = cert_begin + crlPre + end_cert;
        return crlPem;
    }

    public static void writePemCRLToFile(X509CRL x509CRL, String userName) throws CertificateEncodingException, IOException, CRLException {
        FileWriter fw = new FileWriter("src" + File.separator + "CRLLists" + File.separator + userName + "crl.pem");
        fw.write(x509CRLToPemFile(x509CRL));
        fw.close();
    }

    public static X509Certificate getCertFromKeyStore(String keyStore, String storePass) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {

        File file = new File(keystoreFileLocation + File.separator + keyStore);
        InputStream stream = new FileInputStream(file);
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(stream, storePass.toCharArray());
        String alias=keyStore.substring(0,keyStore.indexOf("."));
        Certificate certificate = store.getCertificate(alias);
        X509Certificate x509Certificate = (X509Certificate) certificate;
        return x509Certificate;


    }

    public static void replaceFileLine(String certName,String storePass) {
        try {
            // input the (modified) file content to the StringBuffer "input"
            BufferedReader file = new BufferedReader(new FileReader(numberOfLoginLocation));
            StringBuffer inputBuffer = new StringBuffer();
            String line;

            while ((line = file.readLine()) != null) {

                if (line.substring(0, line.indexOf("#")).equals(certName)) {
                    if (line.substring(line.indexOf("#") + 1, line.length()).equals("0")) {
                        line = certName + "#" + "1";
                    } else if (line.substring(line.indexOf("#") + 1, line.length()).equals("1")) {
                        line = certName + "#" + "2";
                    } else {
                        String keyStoreName = line.substring(0, line.indexOf("#"));
                        line = certName + "#" + "3";
                       String caName = getCAName(keyStoreName, storePass).substring(3,6);

                        if (caName.equals("CA1")) {
                            X509CRL x509CRL=createCRL(readCRLFromFile("CA1"), getCertFromKeyStore(keyStoreName, storePass), readPrivateKeyFromFile("CA1.key"), getSerialNumber(keyStoreName, storePass));
                            writePemCRLToFile(x509CRL,"CA1");
                        } else {
                            X509CRL x509CRL= createCRL(readCRLFromFile("CA2"), getCertFromKeyStore(keyStoreName, storePass), readPrivateKeyFromFile("CA2.key"), getSerialNumber(keyStoreName, storePass));
                            writePemCRLToFile(x509CRL,"CA2");
                        }
                    }
                    }
                    inputBuffer.append(line);
                    inputBuffer.append('\n');
                }

                file.close();


                FileOutputStream fileOut = new FileOutputStream(numberOfLoginLocation);
                fileOut.write(inputBuffer.toString().getBytes());
                fileOut.close();


        }catch (Exception e) {
            System.out.println("Problem reading file.");
        }
    }

    public static boolean isCertificateRevoked(X509CRL x509CRL,X509Certificate x509Certificate){
        X509CRLEntry revokedCertificate = null;
        boolean isRevoked=false;
        revokedCertificate = x509CRL.getRevokedCertificate(x509Certificate.getSerialNumber());
        if(revokedCertificate!=null)
            isRevoked=true;
        return isRevoked;
    }




}
