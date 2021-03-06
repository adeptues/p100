package com.adeptues.devices;

public class DeviceError extends Exception{



    public DeviceError(String message) {
        super(message);
    }

    public DeviceError(String message, Throwable cause) {
        super(message, cause);
    }

    public DeviceError(Throwable cause) {
        super(cause);
    }

    public DeviceError(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
