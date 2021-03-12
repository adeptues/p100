# P100 Tapo

This is a java implementation for the tapo p100 iot power switch.

ported from https://github.com/fishbigger/TapoP100

API is similar

Usage

```java
public class Main {
    public static void main(String[] args) {
        PlugP100 plugP100 = new PlugP100("192.168.x.x", "example@googlemail.com", "Password1");
        plugP100.handshake();
        plugP100.login();
        plugP100.turnOn();
        Thread.sleep(5000);
        plugP100.turnOff();
    }

}

```