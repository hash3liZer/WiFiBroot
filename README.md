![wifibroot](https://user-images.githubusercontent.com/29171692/45045286-eee92680-b08b-11e8-9d0a-cf3d4ee2cd5f.jpeg)

A WiFi-Penetest-Cracking tool for WPA/WPA2 (Handshake, PMKID, Offline Cracking, EAPOLS) 

## DESCRIPTION
WiFiBroot is built to provide clients all-in-one facility for cracking WiFi (WPA/WPA2) networks. It heavily depends on **scapy**, a well-featured packet manipulation library in Python. Almost every process within is dependent somehow on scapy layers and other functions except for operating the wireless interface on a different channel. That will be done via native linux command **iwconfig** for which you maybe need *sudo* privileges. It currently provides three independent working modes to deal with the target networks. Two of them are online cracking methods while the other runs in offline mode. The offline mode is provided to crack saved hashes from the first two modes. It can be run on a variety of linux platforms and atleast requires WN727N from tp-link to properly operate. 

## Installation: 

WiFiBroot heavily depends on scapy. So, you would need scapy installed. Almost, every other library would likely be installed on your system. Make sure the version you install for scapy should be `>=2.4.0`. Previous versions are likely to throw some unknown errors.

```
$ sudo pip install scapy
```
The script is supposed to be run under **sudo** but it will still work even if not run under the root mode. The basic necessary arguments are: 

```
$ sudo python wifibroot.py -i [interface] -d /path/to/dictionary -m [mode]
``` 

## Documentation : ##

WiFiBroot uses modes to identify which attack you want to perform on your target. Currently, there are three available modes. The usage of each mode can be seen by supplying the **--help/-h** option right after the **-m/--mode** option. Here's a list of available modes and what they do: 

### Modes:
```
Syntax:
    $ python wifibroot.py [--mode [modes]] [--options]
    $ python wifibroot.py --mode 2 -i wlan1mon --verbose -d /path/to/list -w pmkid.txt

Modes:
    #     Description                                 Value
    01    Capture 4-way handshake and crack MIC code    1
    02    Captures and Crack PMKID (PMKID Attack)       2
    03    Perform Manaul cracking on available
          capture types. See --list-types               3

Use -h, --help after -m, --mode to get help on modes. 
```
Each mode has a specific purpose and has it's own options: 
### HANDSHAKE: 
```
Mode: 
   01      Capture 4-way handshake and crack MIC code    1

Options:
   Args               Description                      Required
   -h, --help         Show this help manual              NO
   -i, --interface    Monitor Interface to use           YES
   -v, --verbose      Verbose Mode. Detail help          NO
   -t, --timeout      Time Delay between two deauth
                      requests.                          NO
   -d, --dictionary   Dictionary for Cracking            YES
   -w, --write        Write Captured handshake to
                      a seperate file                    NO
       --deauth       Number of Deauthentication
                      frames to send                     NO 

Filters: 
   -e, --essid         ESSID of listening network
   -b, --bssid         BSSID of target network.
   -c, --channel       Channel interface should be listening
                       on. Default: ALL
```
### PMKID ATTACK
```
Mode: 
   02      Captures and Crack PMKID (PMKID Attack)       1

Options:
   Args               Description                      Required
   -h, --help         Show this help manual              NO
   -i, --interface    Monitor Interface to use           YES
   -v, --verbose      Verbose Mode. Detail help          NO
   -d, --dictionary   Dictionary for Cracking            YES
   -w, --write        Write Captured handshake to
                      a seperate file                    NO

Filters: 
   -e, --essid         ESSID of listening network
   -b, --bssid         BSSID of target network.
   -c, --channel       Channel interface should be listening
                       on. Default: ALL
```
### Offline Cracking
```
Mode: 
   03    Perform Manaul cracking on available capture
         types. See --list-types                         3

Options:
   Args               Description                      Required 
   -h, --help         Show this help manual              NO
       --list-types   List available cracking types      NO
       --type         Type of capture to crack           YES
   -v, --verbose      Verbose Mode. Detail help          NO
   -d, --dictionary   Dictionary for Cracking            YES
   -e, --essid        ESSID of target network. 
                      Only for HANDSHAKE Type            YES
   -r, --read         Captured file to crack             YES
```
### Examples

To Capture 4-way handshake and crack MIC code: 
```
$ python wifibroot.py --mode 1 -i wlan1mon --verbose -d dicts/list.txt -w output.cap 
```
To Capture and Crack PMKID:
```
$ python wifibroot.py --mode 2 -i wlan1mon --verbose -d dicts/list.txt -w output.txt
```
Offline Crack Handshake and PMKID:
```
$ python wifibroot.py --mode 3 --type handshake --essid "TARGET ESSID" --verbose -d dicts/list.txt --read output.cap
$ python wifibroot.py --mode 3 --type pmkid --verbose -d dicts/list.txt --read output.txt
```

## Support ##

Website: [https://www.shelvoide.com](https://www.shellvoide.com)

Twitter: [@hash3liZer](https://twitter.com/hash3liZer)

Email: [admin@shellvoide.com](mailto://admin@shellvoide.com) 
