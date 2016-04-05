package com.android.privatechat;


import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class provides encryption/decryption logic
 */
public class Encryption {

    private static final String TAG = "Encryption";

    public static final String FILE_ENCRYPTION_PREFIX = ".encrypted";
    public static final String PASSWORD_4DIGIT_DEFAULT = "0000";

    private static final String RSA = "RSA";
    private static final int RSA_KEY_LENGTH = 2048;

    private static final String ENCRYPTION_AES = "AES";
    private static final String ENCRYPTION_SHA1 = "SHA-1";
    private static final String ENCRYPTION_SALT = "fucking_static_salt";
    private static final String ENCODING_UTF8 = "UTF-8";
    private static final int SECRET_KEY_LENGTH_BYTE = 16; // 128 bits

    private static String getSalt() {
        return ENCRYPTION_SALT;
    }

    public class RSA {
        private KeyPair keyPair;

        public void generateKeys() throws NoSuchAlgorithmException {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
            keyPairGenerator.initialize(RSA_KEY_LENGTH);

            keyPair = keyPairGenerator.genKeyPair();
        }

        public String encrypt(Key publicKey, String string) throws
                NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

            Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] cipherData = cipher.doFinal(string.getBytes());

            return Base64.encodeToString(cipherData, Base64.DEFAULT);
        }

        public Key getPublicKey() throws NullPointerException {
            if (keyPair == null) {
                throw new NullPointerException("KeyPair have not been initialized. Do it with RSA#generateKeys()");
            }
            return keyPair.getPublic();
        }

        public Key getPrivateKey() throws NullPointerException {
            if (keyPair == null) {
                throw new NullPointerException("KeyPair have not been initialized. Do it with RSA#generateKeys()");
            }
            return keyPair.getPrivate();
        }

    }

    public class AES {
        public String encrypt(String secretKey, File file) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
            String filePath = file.getPath() + FILE_ENCRYPTION_PREFIX;

            // Create new output File
            File newFile = new File(filePath);

            // Creating new streams
            FileInputStream fileInputStream = new FileInputStream(file);
            FileOutputStream fileOutputStream = new FileOutputStream(newFile);

            // Create new instance of SecretKeySpec with user's secretKey
            SecretKeySpec secretKeySpec = new SecretKeySpec(SHA1.getKeyFromString(secretKey), ENCRYPTION_AES);

            // Create new instance of Cipher
            Cipher cipher = Cipher.getInstance(ENCRYPTION_AES);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

            // Wrap the output stream
            CipherOutputStream cipherOutputStream = new CipherOutputStream(fileOutputStream, cipher);

            // Write encrypted file
            int byteCount;
            int byteOffset = 0;
            byte[] buffer = new byte[8];
            while ((byteCount = fileInputStream.read(buffer)) != -1) {
                cipherOutputStream.write(buffer, byteOffset, byteCount);
            }

            // Flush and close streams.
            cipherOutputStream.flush();
            cipherOutputStream.close();
            fileInputStream.close();

            // Delete old file
            if (file.delete()) {
                Log.d(TAG, "encrypt() -> Original file deleted");
            } else {
                Log.e(TAG, "encrypt() -> Error while deleting original file");
            }

            return filePath;
        }

        public String encrypt(String value) {
            try {
                IvParameterSpec ivParameterSpec = new IvParameterSpec(SHA1.getKeyFromString(getSalt()));
                SecretKeySpec secretKeySpec = new SecretKeySpec(SHA1.getKeyFromString(value), ENCRYPTION_AES);

                Cipher cipher = Cipher.getInstance(ENCRYPTION_AES);
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

                byte[] encrypted = cipher.doFinal(value.getBytes());
                Log.d(TAG, "encrypted string: " + Base64.encodeToString(encrypted, Base64.DEFAULT));

                return Base64.encodeToString(encrypted, Base64.DEFAULT);
            } catch (Exception ex) {
                Log.e(TAG, "encrypt() -> ", ex);
            }

            return null;
        }

        public String decrypt(String secretKey, File file) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
            String filePath = file.getPath().replace(FILE_ENCRYPTION_PREFIX, "");

            // Create new output File
            File newFile = new File(filePath);

            // Creating new streams
            FileInputStream fileInputStream = new FileInputStream(file);
            FileOutputStream fileOutputStream = new FileOutputStream(newFile);

            // Create new instance of SecretKeySpec with user's secretKey
            SecretKeySpec secretKeySpec = new SecretKeySpec(SHA1.getKeyFromString(secretKey), ENCRYPTION_AES);

            // Create new instance of Cipher
            Cipher cipher = Cipher.getInstance(ENCRYPTION_AES);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

            // Wrap the output stream
            CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);

            // Write encrypted file
            int byteCount;
            int byteOffset = 0;
            byte[] buffer = new byte[8];
            while ((byteCount = cipherInputStream.read(buffer)) != -1) {
                fileOutputStream.write(buffer, byteOffset, byteCount);
            }

            // Flush and close streams.
            fileOutputStream.flush();
            fileOutputStream.close();
            cipherInputStream.close();

            // Delete old file
            if (file.delete()) {
                Log.d(TAG, "decrypt() -> Original file deleted");
            } else {
                Log.e(TAG, "decrypt() -> Error while deleting original file");
            }

            return filePath;
        }
    }

    public static class SHA1 {

        private static byte[] getKeyFromString(String stringKey) throws UnsupportedEncodingException, NoSuchAlgorithmException {
            byte[] key = (getSalt() + stringKey).getBytes(ENCODING_UTF8);
            MessageDigest sha = MessageDigest.getInstance(ENCRYPTION_SHA1);

            key = sha.digest(key);
            key = Arrays.copyOf(key, SECRET_KEY_LENGTH_BYTE); // use only first 128 bits

            return key;
        }
    }
}
