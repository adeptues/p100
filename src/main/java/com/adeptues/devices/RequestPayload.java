package com.adeptues.devices;

import java.time.Instant;
import java.util.Map;

public class RequestPayload extends HandshakePayload {
    private long requestTimeMils;


    public RequestPayload(String method, Map<String, Object> params) {
        super(method, params);
        this.requestTimeMils = Instant.now().toEpochMilli();
    }

    public long getRequestTimeMils() {
        return requestTimeMils;
    }

    public void setRequestTimeMils(long requestTimeMils) {
        this.requestTimeMils = requestTimeMils;
    }
}
