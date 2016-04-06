package com.android.privatechat.Encryption;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Created by root on 4/6/16.
 */
public class SHA1 {
    public static byte[] getKeyFromString(String stringKey) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        byte[] key = (Encryption.getSalt() + stringKey).getBytes(Encryption.ENCODING_UTF8);
        MessageDigest sha = MessageDigest.getInstance(Encryption.ALGORITHM_SHA1);

        key = sha.digest(key);
        key = Arrays.copyOf(key, Encryption.SECRET_KEY_LENGTH_BYTE); // use only first 128 bits

        return key;
    }
}
