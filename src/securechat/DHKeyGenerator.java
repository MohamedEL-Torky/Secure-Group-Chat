/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securechat;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

/**
 *
 * @author Mohamed ELTorky
 */
public class DHKeyGenerator {

    private KeyPairGenerator mKeyGen;
    private PublicKey mPublicKey;
    private PrivateKey mPrivateKey;
    private KeyPair mKeyPair;
    private KeyAgreement mDHAgreement;
    private byte[] mSharedSecret;

    //Used when there is no agreement created yet
    DHKeyGenerator() throws NoSuchAlgorithmException, InvalidKeyException {
        mKeyGen = KeyPairGenerator.getInstance("DH");
        mKeyGen.initialize(2048);

        mKeyPair = mKeyGen.generateKeyPair();
        mPublicKey = mKeyPair.getPublic();
        mPrivateKey = mKeyPair.getPrivate();

        mDHAgreement = KeyAgreement.getInstance("DH");
        mDHAgreement.init(mKeyPair.getPrivate());
    }

    DHKeyGenerator(byte[] encodedSenderKU) throws NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException {

        KeyFactory mKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(encodedSenderKU);
        PublicKey senderKU = mKeyFac.generatePublic(x509KeySpec);
        /*
         * Reciver gets the DH parameters associated with sender's public key.
         * Reciver must use the same parameters when he generates his own key
         * pair.
         */
        DHParameterSpec dhParamFromSenderKU = ((DHPublicKey) senderKU).getParams();

        mKeyGen = KeyPairGenerator.getInstance("DH");
        mKeyGen.initialize(dhParamFromSenderKU);

        mKeyPair = mKeyGen.generateKeyPair();
        mPublicKey = mKeyPair.getPublic();
        mPrivateKey = mKeyPair.getPrivate();

        mDHAgreement = KeyAgreement.getInstance("DH");
        mDHAgreement.init(mKeyPair.getPrivate());
        mDHAgreement.doPhase(senderKU, true);
        mSharedSecret = mDHAgreement.generateSecret();
    }

    //Used by the caller who used the empty constructor
    public void setupAgreement(byte[] encodedSenderKU) throws NoSuchAlgorithmException,
            InvalidKeySpecException, InvalidKeyException {
        KeyFactory mKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(encodedSenderKU);
        PublicKey senderKU = mKeyFac.generatePublic(x509KeySpec);
        mDHAgreement.doPhase(senderKU, true);
        mSharedSecret = mDHAgreement.generateSecret();
    }

    public byte[] getSharedSecret() {
        return mSharedSecret;
    }

    public KeyAgreement getKeyAgreement() {
        return mDHAgreement;
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
