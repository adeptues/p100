package com.adeptues.devices;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.CipherSpi;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class PlugP100 {

    private String ipAddress;
    private String email;
    private String password;
    private String encodedPasswordd;
    private String encodeEmail;
    private String privateKey;
    private String publicKey;
    private ObjectMapper objectMapper;
    private OkHttpClient client;
    private TPLinkCipher tpLinkCipher;
    private String cookie;
    public static final MediaType JSON
    = MediaType.get("application/json; charset=utf-8");
    public  static String REQUEST_MILLIS = "requestTimeMils";
    public  static String KEY = "key";

    public PlugP100(String ipAddress, String email, String password) throws NoSuchAlgorithmException {
        this.objectMapper = new ObjectMapper();
        this.ipAddress = ipAddress;
        this.email = email;
        this.password = password;
        this.encryptCredentials(email,password);
        KeyPair keyPair = this.createKeyPair();
        this.publicKey = TPLinkCipher.mimeEncoder(keyPair.getPublic().getEncoded());
        this.privateKey = TPLinkCipher.mimeEncoder(keyPair.getPrivate().getEncoded());
        this.client = new OkHttpClient();
        this.encryptCredentials(email,password);

    }

    private void encryptCredentials(String email, String password){
        this.encodedPasswordd = TPLinkCipher.mimeEncoder(password.getBytes());
        this.encodeEmail = TPLinkCipher.mimeEncoder(DigestUtils.sha1Hex(email).getBytes());

    }

    private KeyPair createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public void login() throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        String url = "http://"+ipAddress+"/app";
        Map<String,String> params = new HashMap<>();
        params.put("username",encodeEmail);
        params.put("password",encodedPasswordd);
        RequestPayload requestPayload = new RequestPayload("login_device",params);
        String toBeEncrypted = objectMapper.writeValueAsString(requestPayload);
        String encr = this.tpLinkCipher.encrypt(toBeEncrypted);

        SecurePassThroughPayload securePassThroughPayload = new SecurePassThroughPayload(encr);
        String json = objectMapper.writeValueAsString(securePassThroughPayload);
        String response = doPost(url,json);
        System.out.println("response");
        System.out.println(response);
        String field = getFieldFromResponse(response,"response");
        String decrypted = tpLinkCipher.decrypt(field);
        System.out.println(decrypted);
        //encrypt json
        //create securepathtrough
        //make request
        //decrypt response

    }

    public void handshake() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        String url = "http://"+ipAddress+"/app";
        Map<String, String> params = new HashMap<String, String>();
        System.out.println(this.publicKey);
        params.put(KEY,pem(this.publicKey));
        long millis = Instant.now().toEpochMilli();
        params.put(REQUEST_MILLIS, Long.toString(millis));

        HandshakePayload requestPayload = new HandshakePayload("handshake",params);
        String json = this.objectMapper.writeValueAsString(requestPayload);
        RequestBody body = RequestBody.create(JSON, json);
        // make request
        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .build();

        try (Response response = client.newCall(request).execute()) {
            String responseJson = response.body().string();
            String key = getFieldFromResponse(responseJson,"key");
            this.tpLinkCipher = decodeHandshake(key);
            cookie = getCookie(response.header("Set-Cookie"));
            System.out.println("Cookied "+cookie);
        }



        //get cookie


    }

    private String getCookie(String cookieHeader){
        //might need to keep the time out
        return cookieHeader.substring(0,45);
    }

    private TPLinkCipher decodeHandshake(String handshakeKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //base64decode
        //load PKCS1_v1_5 cipher with the private key
        //create a pkcs1 cipher with our private key to decode the key we got from the server
        //to extract the two peices we need for the tplink cipher
        byte[] keyBytes = Base64.getDecoder().decode(handshakeKey);
        Cipher cipher = Cipher.getInstance("RSA");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAEngine rsaEngine = new RSAEngine();
        /*PKCS1Encoding pkcs1Encoding = new PKCS1Encoding(rsaEngine);
        pkcs1Encoding.init(false, CipherParameters);*/
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(this.privateKey));
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        cipher.init(Cipher.DECRYPT_MODE,privateKey);

        byte [] decrypted = cipher.doFinal(keyBytes);
        String kk = new String(decrypted);
        byte [] iv = Arrays.copyOfRange(decrypted,0,16);//maybe off by one
        byte [] key = Arrays.copyOfRange(decrypted,16,32);
        return new TPLinkCipher(iv,key);
    }

    private String getFieldFromResponse(String json,String field) throws JsonProcessingException {
        ResponsePayload responsePayload = objectMapper.readValue(json,ResponsePayload.class);
        return responsePayload.getResult().get(field);
    }

    private String pem(String key){
        StringBuffer stringBuffer = new StringBuffer();
        stringBuffer.append("-----BEGIN PUBLIC KEY-----");
        stringBuffer.append("\r\n");
        stringBuffer.append(key);
        stringBuffer.append("\r\n");
        stringBuffer.append("-----END PUBLIC KEY-----");
        return stringBuffer.toString();
    }

    private String doPost(String url, String payload) throws IOException {
        RequestBody body = RequestBody.create(JSON, payload);
        // make request

        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .header("Cookie",this.cookie)
                .build();

        try (Response response = client.newCall(request).execute()) {
            return response.body().string();
        }
    }


}