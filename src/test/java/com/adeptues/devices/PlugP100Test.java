package com.adeptues.devices;

import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.*;

public class PlugP100Test {

    @Test
    public void handshake() throws NoSuchAlgorithmException, IOException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        PlugP100 plugP100 = new PlugP100("192.168.1.4","adeptues@googlemail.com","Pissoff1");
        plugP100.handshake();
        plugP100.login();//login does not work somthing wrong with length on returned message unable to decrypt
    }
}