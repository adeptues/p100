# Tapo P100 Plug BLE

This document outlines the steps to to register a p100 plug with the wireless network. The end goal here is to be able to register the plug with out using the tapo app from tplink and this avoiding making an yet another account just to use a simple switch.



## bluetooth

when plugged in the for first time the devicer will activate bluetooth noted by the flashing orange and green light this means the device is ready to communicaate over BLE bluetooth low energy.



The tapo appp thne sends aaa services of json objects to the device in the following format



```json
{
    method:"close_device_ble",
    requestTimeMils:1234569,
    terminalUUID:"12-58-48-08-B6-27"
}
```

Where method seems to correspond to a procedure to execute terminalUUID seems to be an id assocaited with the app and requestTimeMils is the time in millis. These 3 fields seem to be mmandatory on any request.

Optional parameters request parameters can be provided as part of the json object when sending method arguments

```json
{
    method:"set_inherit_info",
    params:{
      "is_inherit":false  
    },
    requestTimeMillis:1234569,
    terminalUUID:"12-58-48-08-B6-27"
}
```

The params section seems to be a key value map of possible arguments

## Device discovery

Device discovery seems to involve a special kind of scan from the app to the device as the switch does not broadcast itself like normal bluetooth devices in some kind of handshake discovery phase for the app to be able to find the mac address of the p100

however as the mac address is printed on the back of the switch that can be used directly with the registration scripts.

## Registration Protocol

This section outlines the requests made over bluetooth to get the device on the wifi.

Methods

* qs_component_nego

This is the first request seems to send back some device information aas part of the initial handshake, maybe the app verifies this against tplinks servers?

--

* get_wireless_scan_info
* start_index:0 is a request param

i think this tells the plug to do a wireless scan so the app can ask the user for the credentials it makes two request to this method with different values for the start_index param one as 0 and 10

--

* set_qs_info

  Seems to set the account username and password along with location information

  params 

  ```json
  {
    "account": {
      "password": "cG9vZmFjZQo=",
      "username": "YWRlcHR1ZXNAZ29vZ2xlbWFpbC5jb20="
    },
    "time": {
      "latitude": 531624,
      "longitude": -11352,
      "region": "Europe/London",
      "time_diff": 0,
      "timestamp": 1614716153
    },
    "wireless": {
      "key_type": "wpa2_psk",
      "password": "cG9vZmFjZQo=",
      "ssid": "TkVUR0VBUjkw"
    }
  }
  ```

This is how you set the details for the switch the account details are the details of your tapo/tplink account you make when signing up the password is alarmingly stored as plain text on tplinks side somewhere as it is sent here as base64 a good reason not to use the app.

--

* get_inherit_info

Not sure what this does just responds with `inherit_status:true` 



--

* heart_beat

Presumably it sends this to check its still alive after it told it to configure the wifi and account settings

--

* set_inherit_info

sets `is_inherit:false` on the params, might be related to the get_inherit_info from above not sure what its for.

--

* close_device_ble

tells device to stop bluetooth and go normal settup



* https://github.com/pybluez/pybluez/blob/master/examples/ble/read_name.py
* https://github.com/fishbigger/TapoP100/blob/main/PyP100/PyP100.py
