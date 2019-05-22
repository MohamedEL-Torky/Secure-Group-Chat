/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securechat;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

/**
 *
 * @author Mohamed ELTorky
 */
public class TestGround {

    public static void main(String[] args) throws NoSuchAlgorithmException,
            InvalidKeyException, InvalidKeySpecException,
            GeneralSecurityException, IOException {
        // TODO code application logic here
        PublicKey aliceKU, bobKU;
        PrivateKey aliceKR, bobKR;
        KeyPair aliceKP, bobKP;
        byte[] aliceBytesKU, aliceBytesKR, bobBytesKU, bobBytesKR;

        CertificateGenerator aliceRSA = new CertificateGenerator("RSA");
        aliceKU = aliceRSA.getPublicKey();
        aliceKR = aliceRSA.getPrivate();
        aliceBytesKU = aliceRSA.getPublicKeyBytes();
        aliceBytesKR = aliceRSA.getPrivateKeyBytes();

        //Create Deffie hellman
        DHKeyGenerator aliceDH = new DHKeyGenerator();

        //
        CertificateGenerator bobRSA = new CertificateGenerator("RSA");
        bobKU = bobRSA.getPublicKey();
        bobKR = bobRSA.getPrivate();
        bobBytesKU = bobRSA.getPublicKeyBytes();
        bobBytesKR = bobRSA.getPrivateKeyBytes();

        X509Certificate aliceCert = aliceRSA.generateCertificate("CN=Alice, L=EGYPT, C=EG", 1);
        System.out.println(aliceCert.toString());
        //System.out.println(Arrays.equals(aliceCert.getPublicKey().getEncoded(), aliceBytesKU));
    }
}
