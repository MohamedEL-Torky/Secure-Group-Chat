/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securechat;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import sun.security.x509.*;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

/**
 *
 * @author Mohamed ELTorky
 */
public class CertificateGenerator {

    private KeyPairGenerator mKeyGen;
    private PublicKey mPublicKey;
    private PrivateKey mPrivateKey;
    private KeyPair mKeyPair;
    private String mAlgorithm;

    //ECC
    CertificateGenerator(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        if (algorithm.equals("ECC")) {
            mAlgorithm = "SHA256withECDSA";
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime192v1");
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            mKeyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
            mKeyGen.initialize(ecSpec, new SecureRandom());

            mKeyPair = mKeyGen.genKeyPair();
            mPublicKey = mKeyPair.getPublic();
            mPrivateKey = mKeyPair.getPrivate();
        }
        else if (algorithm.equals("RSA")) {
            mAlgorithm = "SHA256withRSA";
            mKeyGen = KeyPairGenerator.getInstance("RSA");
            mKeyGen.initialize(2048);
            mKeyPair = mKeyGen.genKeyPair();
            mPublicKey = mKeyPair.getPublic();
            mPrivateKey = mKeyPair.getPrivate();
        }
        else {
            System.out.println("Unsupported algorithm!");
        }

    }

    // 256-bit ECC -> equvilant to 3072-bit RSA
    // 384-bit ECC -> equvilant to 7680-bit RSA
    // ECC 384-bit is used to keep Top secret information
    // key size of ECC = max | private key = n
    /**
     * Create a self-signed X.509 Example
     *
     * @param dn the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
     * @param pair the KeyPair
     * @param days how many days from now the Example is valid for
     * @param algorithm the signing algorithm, eg "SHA1withRSA"
     * @return cert the created Certificate
     */
    public X509Certificate generateCertificate(String dn, int days)
            throws GeneralSecurityException, IOException {
        X509CertInfo info = new X509CertInfo();
        Date from = new Date();
        Date to = new Date(from.getTime() + days * 86400000l);
        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger sn = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(dn);

        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
        info.set(X509CertInfo.SUBJECT, owner);
        info.set(X509CertInfo.ISSUER, owner);
        info.set(X509CertInfo.KEY, new CertificateX509Key(mPublicKey));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

        // Sign the cert to identify the algorithm that's used.
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(mPrivateKey, mAlgorithm);

        // Update the algorith, and resign.
        algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        cert = new X509CertImpl(info);
        cert.sign(mPrivateKey, mAlgorithm);
        return cert;
    }

    public KeyPair getKeyPair() {
        return mKeyPair;
    }

    public PublicKey getPublicKey() {
        return mPublicKey;
    }

    public PrivateKey getPrivate() {
        return mPrivateKey;
    }

    public byte[] getPublicKeyBytes() {
        return mPublicKey.getEncoded();
    }

    public byte[] getPrivateKeyBytes() {
        return mPrivateKey.getEncoded();
    }
}
