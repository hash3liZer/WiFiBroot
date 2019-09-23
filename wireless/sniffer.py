import os
import re
import sys
import threading
from scapy.sendrecv import sniff
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import Dot11RSN
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

	def extract_essid(self, pkt):
		layers = pkt.getlayer(Dot11Elt)
		retval = ''
		counter = 0

		try:
			while True:
				layer = layers[counter]
				if hasattr(layer, "ID") and layer.ID == 0:
					retval = layer.info.decode('ascii')
					break
				else:
					counter += 1
		except IndexError:
			pass

		return retval

	def extract_channel(self, pkt):
		layers = pkt.getlayer(Dot11Elt)
		retval = 0
		counter = 0

		try:
			while True:
				layer = layers[counter]
				if hasattr(layer, "ID") and layer.ID == 3 and layer.len == 1:
					retval = ord(layer.info)
					break
				else:
					counter += 1
		except IndexError:
			pass

		return retval

	def extract_power(self, pkt):
		retval = 0

		layer = pkt.getlayer(RadioTap)
		if hasattr(layer, "dBm_AntSignal"):
			retval = layer.dBm_AntSignal

		return retval

	def extract_encryption(self, pkt):
		retval = ''

		if pkt.haslayer(Dot11RSN):
			retval = 'WPA2'

		return retval

	def extract_cipher(self, pkt):
		return

	def extract_auth(self, pkt):
		return

	def filter(self, pkt):
		if pkt.haslayer(Dot11Beacon):
			bssid      = self.extract_bssid(pkt)
			essid      = self.extract_essid(pkt)
			channel    = self.extract_channel(pkt)
			power      = self.extract_power(pkt)
			encryption = self.extract_encryption(pkt)
			cipher     = self.extract_cipher(pkt)
			auth       = self.extract_auth(pkt)

			toappend = {
				'bssid': bssid,
				'essid': essid,
				'channel': channel,
				'power': power,
				'encryption': encryption,
				'cipher': cipher,
				'auth': auth
			}

			if toappend not in self.__ACCESSPOINTS:
				self.__ACCESSPOINTS.append(
					toappend
				)
				print(toappend)

	def sniff(self):
		sniff(iface=self.interface, prn=self.filter)
		sys.stdout.write("\r")