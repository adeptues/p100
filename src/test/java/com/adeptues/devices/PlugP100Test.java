package com.adeptues.devices;

import com.adeptues.p100.PlugP100;
import com.adeptues.p100.TPLinkCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;

public class PlugP100Test {

    @Test
    public void handshake() throws Exception {
        System.out.println(Charset.defaultCharset());
        Security.addProvider(new BouncyCastleProvider());
        PlugP100 plugP100 = new PlugP100("192.168.1.6","adeptues@googlemail.com","Pissoff1");
        plugP100.handshake();
        plugP100.login();//login does not work somthing wrong with length on returned message unable to decrypt
        plugP100.turnOn();
        Thread.sleep(5000);
        plugP100.turnOff();
        String info  = plugP100.getDeviceInfo();
        System.out.println(info);
    }

    @Test
    public void cipherTest() throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        //python iv 91f1c45c8871475c88fdc75d047dc65d
        // 0x91,0xf1,0xc4,0x5c,0x88,0x71,0x47,0x5c,0x88,0xfd,0xc7,0x5d,0x04,0x7d,0xc6,0x5d
        //python key c5d84f6aa1dbc159a269c25e9068455f
        // 0xc5,0xd8,0x4f,0x6a,0xa1,0xdb,0xc1,0x59,0xa2,0x69,0xc2,0x5e,0x90,0x68,0x45,0x5f
        //python data to encrypt {"method": "login_device", "params": {"username": "MmZiZTQ4ZjU4MTA1MTA2YTAxMDgwZjcxYmE5NjFiZmI5MGVlNjUxMw==", "password": "UGlzc29mZjE="}, "requestTimeMils": 1615030507603}
        //python encrypted out lYUs74j4/qaFWkr9KAfOD8qWiD0Dj6e/fVwDRGOX9nhTetE6oStHe8aQfMFrjwZYGBPUFajO8A3SAfnEHhN2sKPdYuQGmc4IvPYxGsAdONvIhwgK8NwpjmBLcaTNK0c4kJPIeI69ImMQN1IA88D3p1BmZOhW835FoJBAmpV/ChGx205Z/kFGq+pw3cPqeHVG1lgEMcymLsuC96q4oq81mIl7gzjqimBmwHQKsaSfgZI=
        Security.addProvider(new BouncyCastleProvider());
        /*byte [] iv = new byte[] {16, 115, -59, -68, 22, 102, -52, -69, 3, 101, 75, -65, -128, -17, -49, -68};
        byte [] key = new byte[] {-118, 46, -52, -66, 75, 43, 78, -65, -50, -53, 79, -66, -82, -119, -50, -66};*/

        byte [] iv = new byte[] {(byte)0xf6,(byte)0x88,(byte)0x23,(byte)0x78,(byte)0x2c,(byte)0xba,(byte)0xa2,(byte)0x78,(byte)0x1e,(byte)0x57,(byte)0x22,(byte)0x78,(byte)0xf3,(byte)0xce,(byte)0x22,(byte)0x78};
        byte [] key = new byte[] {(byte)0x84,(byte)0x4a,(byte)0x26,(byte)0x59,(byte)0xee,(byte)0x83,(byte)0x23,(byte)0x7a,(byte)0x27,(byte)0xb6,(byte)0xa0,(byte)0x78,(byte)0x92,(byte)0x52,(byte)0x22,(byte)0x79};
        TPLinkCipher tpLinkCipher = new TPLinkCipher(iv,key);
        /*String text = "the quick brown fox";
        String encrypted = tpLinkCipher.encrypt(text);
        System.out.println("encrytped");
        System.out.println(encrypted);*/
        String encrypted = "yN9XcurDICjTfqR7EP5/1In13jyowErGHVpqJYttSBI2299ISbP+2F3pACGeSoYvEAMqoPp512isFTuX4l+ImT0jV9HR1xCUSIWvM/58pPz0yM+362rgpQAEymJDNOEeQXyk0OPjF8ROPUjdHXSL3JJARKjh8T8iOL0Zi8vn5H0kjSgsXCK3O8mzOnr4L7gDDB8dYuNOa74OiRge/c+e2VOTmFDxCFXmxKvIBDBu2nQ=";
        String serverString = "7TcFesm/yyholST2OIyRxR66DapjSyQWfvowRfrn5nhLa8Rbikny3QCIVu5jmw7FJEzPonsZvZjBlXE0gtjDh9ixgYfZj4GZvmrQA0ceBAk=";
        String decyrpted = tpLinkCipher.decrypt(serverString);
        System.out.println("decrypted");
        System.out.println(decyrpted);

        //tplink cypher works if supplied with the correct iv and key

    }
}