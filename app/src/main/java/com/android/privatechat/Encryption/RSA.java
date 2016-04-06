package com.android.privatechat.Encryption;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSA {
    private KeyPair keyPair;

    public void generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Encryption.ALGORITHM_RSA);
        keyPairGenerator.initialize(Encryption.RSA_KEY_LENGTH);

        keyPair = keyPairGenerator.genKeyPair();
    }

    public byte[] encrypt(PublicKey publicKey, byte[] aesKey) throws
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(Encryption.ALGORITHM_RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherData = cipher.doFinal(aesKey);

        return cipherData;
    }

    public byte[] decrypt(PrivateKey privateKey, byte[] aesKey) throws
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(Encryption.ALGORITHM_RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] cipherData = cipher.doFinal(aesKey);

        return cipherData;
    }

    public PublicKey getPublicKey() throws NullPointerException {
        if (keyPair == null) {
            throw new NullPointerException("KeyPair have not been initialized. Do it with RSA#generateKeys()");
        }
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() throws NullPointerException {
        if (keyPair == null) {
            throw new NullPointerException("KeyPair have not been initialized. Do it with RSA#generateKeys()");
        }
        return keyPair.getPrivate();
    }
}
