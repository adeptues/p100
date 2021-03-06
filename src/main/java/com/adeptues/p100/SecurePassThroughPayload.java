package com.adeptues.p100;

import java.util.HashMap;

public class SecurePassThroughPayload extends HandshakePayload{
    public SecurePassThroughPayload(String request) {
        super("securePassthrough", new HashMap<>());
        getParams().put("request",request);
    }
}
