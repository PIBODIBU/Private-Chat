package com.android.privatechat.Encryption;

public class Encryption {

    private static final String TAG = "Encryption";

    public static final String FILE_ENCRYPTION_PREFIX = ".encrypted";
    public static final String PASSWORD_4DIGIT_DEFAULT = "0000";

    public static final String ALGORITHM_RSA = "RSA";
    public static final int RSA_KEY_LENGTH = 2048;

    public static final String ALGORITHM_AES = "AES";
    public static final String ALGORITHM_SHA1 = "SHA-1";
    public static final String ENCRYPTION_SALT = "fucking_static_salt";
    public static final String ENCODING_UTF8 = "UTF-8";
    public static final int SECRET_KEY_LENGTH_BYTE = 16; // 128 bits

    public static String getSalt() {
        return ENCRYPTION_SALT;
    }
}
