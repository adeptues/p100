package com.adeptues.p100;

public class Result {
    private Integer error_code;

    public Result(Integer error_code) {
        this.error_code = error_code;
    }

    public Result() {
    }

    public Integer getError_code() {
        return error_code;
    }

    public void setError_code(Integer error_code) {
        this.error_code = error_code;
    }
}
