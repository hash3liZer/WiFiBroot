import os
import re
import sys
import threading
from scapy.sendrecv import sniff
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11FCS
from scapy.layers.eap   import EAPOL

class SNIFFER:

	__ACCESSPOINTS = []
	__STATIONS     = {}

	def __init__(self, interface, channels, essids, aps, stations, filters):
		self.interface = interface
		self.channels  = channels
		self.essids    = essids
		self.aps       = aps
		self.stations  = stations
		self.filters   = filters

	def extract_bssid(self, pkt):
		bssid = ''
		try:
			bssid = pkt.getlayer(Dot11FCS).addr2
		except:
			bssid = pkt.getlayer(Dot11).addr2

		return bssid

	def extract_essid(self):
		essid = ''

	def filter(self, pkt):
		if pkt.haslayer(Dot11Beacon):
			bssid = self.extract_bssid(pkt)
			essid = self.extract_essid(pkt)

	def sniff(self):
		sniff(iface=self.interface, prn=self.filter)
		sys.stdout.write("\r")