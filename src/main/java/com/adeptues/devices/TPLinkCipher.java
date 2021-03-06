package com.adeptues.devices;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import sun.security.pkcs.PKCS7;
import sun.security.pkcs.ParsingException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

public class TPLinkCipher {
    private byte [] iv;
    private byte [] key;

    public TPLinkCipher(byte[] iv, byte[] key) {
        this.iv = iv;
        this.key = key;
    }

    public String encrypt(String data) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //original python code uses pkcs7 padding. this is not available in java but pkcs5 functionally identical for AES
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key,"AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE,secretKeySpec,ivParameterSpec);//cbc_mode in python
        byte [] out = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(out);//in python this ised the mimencoder bust stripped the newlines
    }

    public String decrypt(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key,"AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        //TODO still a problem with padding decryption
        cipher.init(Cipher.DECRYPT_MODE,secretKeySpec,ivParameterSpec);
        byte [] out = cipher.doFinal(Base64.getDecoder().decode(data));
        return new String(out);
    }

    public static String mimeEncoder(byte [] toEncode){
        Base64.Encoder encoder = Base64.getMimeEncoder(64,"\r\n".getBytes());
        return encoder.encodeToString(toEncode);
    }
}
