package com.adeptues.devices;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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
    private String token;
    public static final MediaType JSON
    = MediaType.get("application/json; charset=utf-8");
    public  static String REQUEST_MILLIS = "requestTimeMils";
    public  static String KEY = "key";

    public PlugP100(String ipAddress, String email, String password) throws Exception {
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

    public RSAPrivateKey readPrivateKeySecondApproach(File file) throws IOException {
    try (FileReader keyReader = new FileReader(file)) {

        PEMParser pemParser = new PEMParser(keyReader);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());

        return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
    }
}
public RSAPrivateKey readPrivateKey(File file) throws Exception {
    KeyFactory factory = KeyFactory.getInstance("RSA");

    try (FileReader keyReader = new FileReader(file);
      PemReader pemReader = new PemReader(keyReader)) {

        PemObject pemObject = pemReader.readPemObject();
        byte[] content = pemObject.getContent();
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
        return (RSAPrivateKey) factory.generatePrivate(privKeySpec);
    }
}


public RSAPublicKey readPublicKeySecondApproach(File file) throws IOException {
    try (FileReader keyReader = new FileReader(file)) {
        PEMParser pemParser = new PEMParser(keyReader);
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(pemParser.readObject());
        return (RSAPublicKey) converter.getPublicKey(publicKeyInfo);
    }
}

    private KeyPair createKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        /*File pubKey = new File("/home/tom/tom/p100/src/main/resources/publickey");
        File privKey = new File("/home/tom/tom/p100/src/main/resources/privatekey");
        RSAPublicKey rsaPublicKey = readPublicKeySecondApproach(pubKey);
        RSAPrivateKey rsaPrivateKey = readPrivateKey(privKey);*/
//https://stackoverflow.com/questions/33425446/creating-rsa-public-key-from-string/33426378#33426378
        return keyPair;
    }

    public void login() throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        String url = "http://"+ipAddress+"/app";
        Map<String, Object> params = new HashMap<>();
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
        String token = getFieldFromResponse(decrypted,"token");
        this.token = token;
        //encrypt json
        //create securepathtrough
        //make request
        //decrypt response

    }

    public DeviceInfo getDeviceInfo() throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        String url = "http://"+ipAddress+"/app?token="+token;

        RequestPayload requestPayload = new RequestPayload("get_device_info",null);
        String encryptedPayload = this.tpLinkCipher.encrypt(objectMapper.writeValueAsString(requestPayload));
        SecurePassThroughPayload securePassThroughPayload = new SecurePassThroughPayload(encryptedPayload);
        String responseJson = doPost(url,objectMapper.writeValueAsString(securePassThroughPayload));
        String decyrpted = this.tpLinkCipher.decrypt(getFieldFromResponse(responseJson,"response"));
        String deviceString = getFieldFromResponse(decyrpted,"result");
        return objectMapper.readValue(deviceString,DeviceInfo.class);
    }

    public boolean turnOn() throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        return switchOnOff(true);
    }

    private boolean switchOnOff(boolean on) throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        String url = "http://"+ipAddress+"/app?token="+token;
        Map<String, Object> params = new HashMap<>();
        params.put("device_on",on);
        RequestPayload requestPayload = new RequestPayload("set_device_info",params);

        String encyrptedPayload = this.tpLinkCipher.encrypt(objectMapper.writeValueAsString(requestPayload));
        SecurePassThroughPayload securePassThroughPayload = new SecurePassThroughPayload(encyrptedPayload);

        String responseJson = doPost(url,objectMapper.writeValueAsString(securePassThroughPayload));

        String decryptedPayload = this.tpLinkCipher.decrypt(getFieldFromResponse(responseJson,"response"));
        Result result = objectMapper.readValue(decryptedPayload,Result.class);
        if(result.getError_code() != 0){
            //maybe throw exceptions instead
            return false;
        }
        return true;
    }
    public boolean turnOff() throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        return switchOnOff(false);
    }

    public void handshake() throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException, NoSuchProviderException {
        String url = "http://"+ipAddress+"/app";
        Map<String, Object> params = new HashMap<>();
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

    private TPLinkCipher decodeHandshake(String handshakeKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException, NoSuchProviderException {
        //base64decode
        //load PKCS1_v1_5 cipher with the private key
        //create a pkcs1 cipher with our private key to decode the key we got from the server
        //to extract the two peices we need for the tplink cipher
        byte[] keyBytes = Base64.getDecoder().decode(handshakeKey);
        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding","BC");
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");


        RSAEngine rsaEngine = new RSAEngine();
        PKCS1Encoding pkcs1Encoding = new PKCS1Encoding(rsaEngine);


//        pkcs1Encoding.init(false, CipherParameters);
//        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(this.privateKey.getBytes());
//        InputStreamReader inputStreamReader = new InputStreamReader(byteArrayInputStream);
//        PemObject keyParameter = new PemReader(inputStreamReader).readPemObject();
//        KeyParameter
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Base64.getMimeDecoder().decode(this.privateKey));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(this.privateKey));
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        cipher.init(Cipher.DECRYPT_MODE,privateKey);

        byte [] decrypted = cipher.doFinal(keyBytes);
        String kk = new String(decrypted);
        byte [] iv = Arrays.copyOfRange(decrypted,16,32);//maybe off by one
        byte [] key = Arrays.copyOfRange(decrypted,0,16);
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
