package com.adeptues.p100;

import java.util.Map;

public class ResponsePayload {
    private Integer error_code;
    private Map<String,String> result;

    public ResponsePayload() {
    }

    public Integer getError_code() {
        return error_code;
    }

    public void setError_code(Integer error_code) {
        this.error_code = error_code;
    }

    public Map<String, String> getResult() {
        return result;
    }

    public void setResult(Map<String, String> result) {
        this.result = result;
    }
}
