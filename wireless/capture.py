import os
import re
import sys
import time
import curses
import random
import threading
import subprocess
from tabulate import tabulate
from scapy.sendrecv import sniff
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11Deauth
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import Dot11EltRSN
from scapy.layers.dot11 import Dot11FCS
from scapy.layers.dot11 import Dot11EltMicrosoftWPA
from scapy.layers.dot11 import Dot11EltCountry
from scapy.layers.eap   import EAPOL

class CAPTURE:

	def __init__(self, iface, bssid, essid, channel, power, device, encryption, cipher, auth, stations):
		self.interface = iface
		self.bssid = bssid
		self.essid = essid
		self.channel = channel
		self.power   = power
		self.device  = device
		self.encryption = encryption
		self.cipher  = cipher
		self.auth    = auth
		self.stations = stations

	def channeler(self):
		ch = str(self.channel)
		subprocess.call(['iwconfig', self.interface, 'channel', ch])

	def jammer(self):
		while True:
			pass

	def capture(self, pkt):
		return

	def engage(self):
		t = threading.Thread(target=self.jammer)
		t.daemon = True
		t.start()

		sniff(iface=self.interface, prn=self.capture)