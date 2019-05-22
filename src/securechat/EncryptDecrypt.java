/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package securechat;

import java.io.IOException;
import java.io.Serializable;
import java.security.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Mohamed ELTorky
 */
public class EncryptDecrypt {



    public SealedObject encryptAuthRSAObject(PrivateKey privateKey, Serializable message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return new SealedObject(message, cipher);
    }

    public SealedObject encryptConfRSAObject(PublicKey publicKey, Serializable message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return new SealedObject(message, cipher);
    }

    public Object decryptAuthRSAObject(PublicKey publicKey, SealedObject encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return encrypted.getObject(cipher);
    }

    public Object decryptConfRSAObject(PrivateKey privateKey, SealedObject encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return encrypted.getObject(cipher);
    }
    
    public byte[] encryptConfRSAByte(PublicKey publicKey, byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(encrypted);
    }
    
    public byte[] decryptConfRSAByte(PrivateKey privateKey, byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encrypted);
    }

    //encrypt using AES in CBC mode
    public SealedObject encryptAES(byte[] sharedSecretKey, Serializable message) throws
            NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            IOException {

        SecretKeySpec AESKey = new SecretKeySpec(sharedSecretKey, 0, 16, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, AESKey);

        SealedObject sealdObject = new SealedObject(message, cipher);
        // Since we are using AES in CBC mode which needs IV to start with, then
        // we must keep the IV and send it to the reciver to decrypt with or the
        // decryption will fail.

        return sealdObject;
    }

    public Object decrypt(byte[] sharedSecretKey, SealedObject encrypted) throws
            NoSuchAlgorithmException, IOException, InvalidKeyException,
            NoSuchPaddingException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {

        SecretKeySpec AESKey = new SecretKeySpec(sharedSecretKey, 0, 16, "AES");



        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, AESKey);

        return encrypted.getObject(cipher);
    }


}
