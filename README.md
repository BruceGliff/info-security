# info-security
A tool to test router for attack resistance.
| :exclamation: Disclaimer |
|-|
|This program is for informational puproses only.<br />If you know how these attacks work then you better defender against them.<br />Do not try this on any system that you do not own or have permission to do so.|

Build: ```cmake```\
Launch with root permissions: ```./netcracker```

Work split onto 5 stages:\
1 - Launch:
```
sudo ./bin/netcracker/netcracker
```
2 - Interface selection:
```
 Iface idx | Iface name
    [0]    |    wlan1
    [1]    |    wlan0

Enter interface index: 1
```
3 - AccessPoint selection:
```
Scanning AcessPoints for 5 seconds.
 Idx  Chnl        BSSID             ESSID
[  0] {11} - c4:71:74:32:00:ca   TP-LING_00CA
[  1] {10} - e4:cd:2a:27:ec:17   TP-lionk_EC18
[  2] {13} - 58:d5:6a:b7:df:9f   pwd-825-DF9C
[  3] {02} - 8c:53:c3:a6:8b:a3   PRooF-COMM_9900_2.4G
[  4] {02} - 18:31:bf:36:cc:e0   360_21
[  5] {01} - 9c:9d:7e:18:e8:da   Bootcamp_CSGO_1.6
[  6] {08} - 14:da:e9:f8:d3:1e   GANgS
[  7] {03} - d8:0d:17:03:96:5a   room_508mUp
[  8] {04} - aa:bb:cc:dd:ee:ff   MY_Wanted_AP
[  9] {04} - 7c:8b:ca:da:a7:a4   DS-WiFi-SD
[ 10] {11} - cc:32:e5:06:eb:ba   TP-Link_EBEAT

Enter valid AcessPoint index: 8
```
4 - Scanning selected AP and sending DeauthPacket.
```
Scanning from: aa:bb:cc:dd:ee:ff channel: {4} iface: wlan0mon
44:85:00:ff:9c:39  -- Found new device
44:85:00:ff:9c:39  -- Sending deauth packets
44:85:00:ff:9c:39  -- EAPOL found


All stations: 
44:85:00:ff:9c:39   EAPOL
```
5 - Brute-forcing:
```
Key found: [thisismykey]
```
Requiremets: gcrypt library, genl library.\
Dependencies: ieee80211 structures definition. packet structures definition. API in sha1 algorithm.\
Tested: Linux 5.10.0-kali7-amd64. WiFi iface: iwlwifi - intel wireless card.\
All other network cards will fall. I do not implement logic for them.\
Warnign: This can leave the system in a non-consistent state (unfortunately). Use at your own risk. I don't take any responsibility.
