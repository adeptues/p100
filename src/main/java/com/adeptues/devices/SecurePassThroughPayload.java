package com.adeptues.devices;

import java.util.HashMap;
import java.util.Map;

public class SecurePassThroughPayload extends HandshakePayload{
    public SecurePassThroughPayload(String request) {
        super("securePassthrough", new HashMap<>());
        getParams().put("request",request);
    }
}
