package com.android.privatechat.Encryption;

import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by root on 4/6/16.
 */
public class AES {

    private static String TAG = "AES";

    public static String encrypt(String secretKey, File file) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        String filePath = file.getPath() + Encryption.FILE_ENCRYPTION_PREFIX;

        // Create new output File
        File newFile = new File(filePath);

        // Creating new streams
        FileInputStream fileInputStream = new FileInputStream(file);
        FileOutputStream fileOutputStream = new FileOutputStream(newFile);

        // Create new instance of SecretKeySpec with user's secretKey
        SecretKeySpec secretKeySpec = new SecretKeySpec(SHA1.getKeyFromString(secretKey), Encryption.ALGORITHM_AES);

        // Create new instance of Cipher
        Cipher cipher = Cipher.getInstance(Encryption.ALGORITHM_AES);
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

    public static String encrypt(PublicKey publicKey, String string) throws
            NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(Encryption.ALGORITHM_AES);
        cipher.wrap(publicKey);

        byte[] encrypted = cipher.doFinal(string.getBytes());

        return Base64.encodeToString(encrypted, Base64.DEFAULT);
    }

    public static String encrypt(PrivateKey privateKey, String string) throws
            NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(Encryption.ALGORITHM_AES);
        cipher.wrap(privateKey);

        byte[] encrypted = cipher.doFinal(string.getBytes());

        return Base64.encodeToString(encrypted, Base64.DEFAULT);
    }

    public static String encrypt(String value) {
        try {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(SHA1.getKeyFromString(Encryption.getSalt()));
            SecretKeySpec secretKeySpec = new SecretKeySpec(SHA1.getKeyFromString(value), Encryption.ALGORITHM_AES);

            Cipher cipher = Cipher.getInstance(Encryption.ALGORITHM_AES);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            Log.d(TAG, "encrypted string: " + Base64.encodeToString(encrypted, Base64.DEFAULT));

            return Base64.encodeToString(encrypted, Base64.DEFAULT);
        } catch (Exception ex) {
            Log.e(TAG, "encrypt() -> ", ex);
        }

        return null;
    }

    public static String decrypt(String secretKey, File file) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
        String filePath = file.getPath().replace(Encryption.FILE_ENCRYPTION_PREFIX, "");

        // Create new output File
        File newFile = new File(filePath);

        // Creating new streams
        FileInputStream fileInputStream = new FileInputStream(file);
        FileOutputStream fileOutputStream = new FileOutputStream(newFile);

        // Create new instance of SecretKeySpec with user's secretKey
        SecretKeySpec secretKeySpec = new SecretKeySpec(SHA1.getKeyFromString(secretKey), Encryption.ALGORITHM_AES);

        // Create new instance of Cipher
        Cipher cipher = Cipher.getInstance(Encryption.ALGORITHM_AES);
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
