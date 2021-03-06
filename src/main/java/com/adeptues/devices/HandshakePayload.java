package com.adeptues.devices;

import java.util.Map;

public class HandshakePayload {
     private String method;
    private Map<String, String> params;

    public HandshakePayload(String method, Map<String, String> params) {
        this.method = method;
        this.params = params;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public Map<String, String> getParams() {
        return params;
    }

    public void setParams(Map<String, String> params) {
        this.params = params;
    }
}
