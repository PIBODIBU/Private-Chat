package com.android.privatechat;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import com.android.privatechat.Encryption.RSA;

public class MainActivity extends AppCompatActivity {

    private static String TAG = "MainActivity";

    private RSA client1;
    private RSA client2;

    private String messageFromClient1 = "Hi, I am Client 1!";

    private TextView client1KeyPublic;
    private TextView client1KeyPrivate;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        client1KeyPublic = (TextView) findViewById(R.id.client1_key_public);
        client1KeyPrivate = (TextView) findViewById(R.id.client1_key_private);

        initClient1();
        initClient2();

        sendMessage();
    }

    private void sendMessage() {
        try {
            client1.generateKeys();
            client2.generateKeys();
        } catch (Exception ex) {
            Log.e(TAG, "sendMessage() -> ", ex);
            return;
        }

        String msgOriginal = messageFromClient1;
        String msgEncrypted = "";
        String msgDecrypted = "";
        String keyPublic;
        String keyPrivate;

        try {
            keyPublic = client1.getPublicKey().toString();
            keyPrivate = client2.getPrivateKey().toString();

            client1KeyPublic.setText(keyPublic);
            client1KeyPrivate.setText(keyPrivate);
        } catch (Exception ex) {
            Log.e(TAG, "sendMessage() -> ", ex);
            return;
        }

        Log.d(TAG, "sendMessage() -> " +
                "\nOriginal: " + msgOriginal +
                "\nEncrypted: " + msgEncrypted +
                "\nDecrypted: " + msgDecrypted +
                "\nPublic key: " + keyPublic +
                "\nPrivate key: " + keyPrivate
        );
    }

    private void initClient1() {
        client1 = new RSA();
    }

    private void initClient2() {
        client2 = new RSA();
    }
}
