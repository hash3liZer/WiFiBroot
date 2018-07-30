# WiFiBroot - Cracking WPA/WPA2
An extensive Tool for Cracking WPA/WPA2, managing handshakes and computing hashes.

![WiFiBroot](https://user-images.githubusercontent.com/29171692/43396374-bead0ee2-941a-11e8-82d4-76061ccbfe96.png)


## DESCRIPTION
WiFiBroot is an extensive research tool for WPA/WPA2 cracking and currently is under development. The version above provided may have some glitches while being designed. So, you are very my much welcome to contribute in this project by reporting anything you find unusual. WiFiBroot uses the handshakes along with provided dictionaries to crack passwords by computing various hashes like PMK, PTK, KCK and MIC etc. It uses linux device files and some internal linux commands to interact with the monitor interface. Further, it uses it own built-in wireless sniffer that sniffs wireless packets and further manipulates them. It works by first identifying networks in an area, choose one of them as target, tries to capture handshakes by sending deauth packets from AP to client and vice virsa and at the end, tries to guess the passwords by computing EAPOL hashes. 

### Features :

* Native Packet manipulation.
* Sort clients and APs according to reported power and accordingly perform further action. Provides stability.
* Auto-detect EAPOL and auto-send dissociation frames.
* Store handshakes in a seperate directory.
* Supports verbose mode

### Drawback :

* As of it is built in Python, you may not be able to acheive the speed of other C utilities like coWPAtty and aircrack.

## Documentation : ##

All you need to have a kick start is a wireless card thats supports packet injection in monitor mode. Usual Usage: 

```
$ sudo python wifibroot.py -i wlan1mon
```
### Dependencies : ###

WiFiBroot heavily depends on scapy. So, you would need scapy installed. Almost, every other library will be already installed on your system: 

```
$ sudo pip install scapy
```
The script must be run under root privileges for the interface necassities. If you fell suppressed with this configuration, you can edit a few lines of verification in the source code. 

### Usage ###

Normal Usage: 
```
$ sudo python wifibroot.py -i wlan1mon [options]
```
All options:
```
  -h, --help            show this help message and exit
  -i INTERFACE, --interface=INTERFACE
                        Monitor Interface to use.
  -e ESSID, --essid=ESSID
                        Targets AP's with the specified ESSIDs
  -b BSSID, --bssid=BSSID
                        Targets AP's with the specified BSSIDs
  -c CHANNEL, --channel=CHANNEL
                        Listen on specified Channel.
  -p PASSWORD, --password=PASSWORD
                        Check the AP against provided WPA Key Passphrase. 
  -d DICTIONARY, --dictionary=DICTIONARY
                        Dictionary containing Passwords
  --newhandshake        Discard previous handshake and capture new one.
  -n, --nowrite         Do not Save the Captured Handshakes
  -v, --verbose         Verbose Mode. More information and print hashes. 
```
Under normal mode, it will print out a few important details and will print password if found. For research facilities, verbose mode will show you live packets as soon as they get captured and will print hexdump of computed hashes. The hashes will include, PMK (Pairwise Master Key), PTK (Pairwise Transient Key) and MIC (Message Integrity Code). An example given below: 

![hashes](https://user-images.githubusercontent.com/29171692/43396478-2340e7c0-941b-11e8-9077-7f3992968eb7.png)

## Support ##

Website: [https://www.shelvoide.com](https://www.shellvoide.com)

Twitter: [@hash3liZer](https://twitter.com/hash3liZer)

Email: [admin@shellvoide.com](mailto://admin@shellvoide.com) 
