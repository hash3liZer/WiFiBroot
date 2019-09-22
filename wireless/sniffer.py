import os
import re
import sys
from scapy.sendrecv import sniff
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11FCS
from scapy.layers.eap   import EAPOL

class SNIFFER:

	def __init__(self, interface, channels, essids, aps, stations, filters):
		self.interface = interface
		self.channels  = channels
		self.essids    = essids
		self.aps       = aps
		self.stations  = stations
		self.filters   = filters

	def sniff(self):
		return