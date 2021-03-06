package com.adeptues.p100;

import java.util.Map;

public class HandshakePayload {
     private String method;
    private Map<String, Object> params;

    public HandshakePayload(String method, Map<String, Object> params) {
        this.method = method;
        this.params = params;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public Map<String, Object> getParams() {
        return params;
    }

    public void setParams(Map<String, Object> params) {
        this.params = params;
    }
}
