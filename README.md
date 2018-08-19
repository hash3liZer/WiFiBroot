# WiFiBroot - Cracking WPA/WPA2
An extensive Tool for Cracking WPA/WPA2, managing handshakes and computing hashes and this is a proof of concept that half of the handshake can be used to crack WPA/WPA2. 

![WiFiBroot](https://user-images.githubusercontent.com/29171692/43396374-bead0ee2-941a-11e8-82d4-76061ccbfe96.png)

## DESCRIPTION
WiFiBroot is an extensive research tool for **WPA/WPA2** cracking and currently is under development. The version above provided may have some glitches while being designed. So, you are very my much welcome to contribute in this project by reporting anything you find unusual. WiFiBroot uses the handshakes along with provided dictionaries to crack passwords by computing various hashes like **PMK, PTK, KCK** and **MIC** etc. It uses linux device files and some internal linux commands to interact with the monitor interface. Further, it uses it own built-in wireless sniffer that sniffs wireless packets and further manipulates them. It works by first identifying networks in an area, choose one of them as target, tries to capture handshakes by sending deauth packets from AP to client and vice virsa and at the end, tries to guess the passwords by computing EAPOL hashes. 

### Features :

* Native Packet manipulation.
* Sort clients and APs according to reported power and accordingly perform further action. Provides stability.
* Auto-detect EAPOL and auto-send dissociation frames.
* Store handshakes in a seperate directory.
* Supports verbose mode

### Drawback :

* As of it is built in Python, you may not be able to acheive the speed of other C utilities like coWPAtty and aircrack.

## Installation: 

WiFiBroot heavily depends on scapy. So, you would need scapy installed. Almost, every other library would likely be installed on your system: 

```
$ sudo pip install scapy
```
The script must be run under **root** privileges for the interface necassities. If you fell suppressed with this configuration, you can edit a few lines of verification in the source code.

And then run the script: 

```
$ sudo python wifibroot.py -i wlan1mon
```

## Documentation : ##

Here, is the complete documentation for using wifibroot: 

### Usage:

Normal Usage: 
```
$ sudo python wifibroot.py -i wlan1mon [options]
```
Options: 
```
General:
    -h, --help          Show this help Manual. 
    -i, --interface     Monitor Interface to use
    -m, --mode          WiFiBroot mode, Default: 1
                        See below information.      
    -v, --verbose       Verbose Mode. Print hashes too. 
    -t, --timeout       Timeout for clients detection.
                        Default: 20
        --nowrite       Do not save the handshake after
                        it is captured
        --newhandshake  Capture new handshake discard 
                        previous one
        --deauth        Number of deauthentication packets
                        to send. Default: 32
    -p, --passwords     Comma Seperated list of passwords
                        instead of dictionary
    -d, --dictionary    Use this dictionary instead of
                        default one.

Filters: 
    -e, --essid         ESSID of listening network
    -b, --bssid         BSSID of target network.
    -c, --channel       Channel interface should be listening
                        on. Default: ALL

Handshake Mode (4 EAPOLS):
    This mode requires to first capture the handshake 
    and then accordingly crack the hash. 

    -m, --mode          Must be 1 in this case

Cracking Mode (PMKID):
    This Mode does not require handshake to be captured. 
    Fast and more reliable. Works with WPA2 networks. 

    -m, --mode          Must be 2 in this case
```
Under normal mode, it will print out a few important details and will print password if found. For research facilities, verbose mode will show you live packets as soon as they get captured and will print hexdump of computed hashes. The hashes will include, PMK (Pairwise Master Key), PTK (Pairwise Transient Key) and MIC (Message Integrity Code). An example given below: 

![hashes](https://user-images.githubusercontent.com/29171692/43396478-2340e7c0-941b-11e8-9077-7f3992968eb7.png)

### Filtering Networks

For filtering networks or specifying the targets, the script provides you with three options:  `ESSID`, `BSSID` and `Channel` where ESSID specifies the name of networks while **BSSID** specifies MAC. For more deepin network search, you can provide both 3 options at a time. Here's an example where i've specifed the essid "PTCL-BB" and here i got expected results. The same applies with other two options. 

```
$ sudo python wifibroot.py -i wlan1mon --essid "Target Name"
```

![filtering](https://user-images.githubusercontent.com/29171692/43587225-1e7c099e-9683-11e8-82d7-a6dd2c628354.png)

### Generating Handshake

Of course, the most important thing so far is generating successful handshakes. By default, the script will listen for **20** seconds on the interface for connections between Access Point and other devices. Devices are lined up according to the generated traffic and then again lined up by according to the range reported by the interface. This enables the script to increase the chances of generating handshake in less time. You can provide `timeout` option here to set your own time for listening on to the clients. 

```
# Will listen for 50 seconds. 
$ sudo python wifibroot.py -i wlan1mon -t 50
```

### Cracking

To Crack the password, there is a built-in dictionary in the folder **dicts** which contain some of the most dumb password from the previous years. In extension to that, wifibroot also check for default passwords which increase it's credibility of finding the right hash. At this stage, you can provide your own dictionary or pass a comma seperated string to `-p` argument: 

```
# Providing Dictionary: 
$ python wifibroot.py -i wlan1mon -d /path/to/dict

# Passwing Passwords from console: 
$ python wifibroot.py -i wlan1mon -p "password,anotherpassword,password2"  # And so on ... 
```

### Cracking through PMKID
A recent loophole discovery in WPA2 which was discovered by Jens Steube the owner of hashcat tool has been recently added to the script in Version 1.1. All the process remains same, what changes is just the mode paramter. To run the script in pmkid mode: 

```
$ python wifibroot --mode 2 --verbose --dictionary /path/to/file
```
### Research Mode: 

There's a verbose mode provided which can help you see the computed hashes for the found key and will print Live packets while sniffing which will add more stability for you to see information in detail: 

```
$ python wifibroot.py -i wlan1mon --verbose
```

## Support ##

Website: [https://www.shelvoide.com](https://www.shellvoide.com)

Twitter: [@hash3liZer](https://twitter.com/hash3liZer)

Email: [admin@shellvoide.com](mailto://admin@shellvoide.com) 
