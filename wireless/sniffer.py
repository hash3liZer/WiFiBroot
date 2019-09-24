import os
import re
import sys
import time
import random
import threading
import subprocess
from scapy.sendrecv import sniff
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import Dot11EltRSN
from scapy.layers.dot11 import Dot11FCS
from scapy.layers.dot11 import Dot11EltMicrosoftWPA
from scapy.layers.eap   import EAPOL

class SNIFFER:

	__ACCESSPOINTS = {}

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

		if pkt.haslayer(Dot11EltRSN):
			retval = 'WPA2'

		if pkt.haslayer(Dot11EltMicrosoftWPA):
			retval += '/WPA' if retval else 'WPA'

		if not retval:
			try:
				cap = str(pkt.getlayer(Dot11FCS).cap)
			except:
				cap = str(pkt.getlayer(Dot11).cap)

			if "privacy" in cap.split("+"):
				retval = 'WEP'
			else:
				retval = 'OPN'

		return retval
	def extract_cipher(self, pkt):
		retval = ''
		aciphers = {
			1: 'WEP',
			2: 'TKIP',
			4: 'CCMP',
			5: 'WEP'
		}

		if pkt.haslayer(Dot11EltRSN):
			rsnlayer = pkt.getlayer(Dot11EltRSN)
			ciphers  = rsnlayer.pairwise_cipher_suites

			for cipher in ciphers:
				retval += aciphers.get(cipher.cipher) if not retval else ("/"+aciphers.get(cipher.cipher))

		elif pkt.haslayer(Dot11EltMicrosoftWPA):
			wpalayer = pkt.getlayer(Dot11EltMicrosoftWPA)
			ciphers  = wpalayer.pairwise_cipher_suites

			for cipher in ciphers:
				retval += aciphers.get(cipher.cipher) if not retval else ("/"+aciphers.get(cipher.cipher))

		return retval

	def extract_auth(self, pkt):
		retval = ''
		aakms = {
			1: 'MGT',
			2: 'PSK'
		}

		if pkt.haslayer(Dot11EltRSN):
			rsnlayer = pkt.getlayer(Dot11EltRSN)
			akms     = rsnlayer.akm_suites

			for akm in akms:
				retval += aakms.get(akm.suite) if not retval else ("/"+akms.get(akm.suite))

		elif pkt.haslayer(Dot11EltMicrosoftWPA):
			rsnlayer = pkt.getlayer(Dot11EltMicrosoftWPA)
			akms     = rsnlayer.akm_suites

			for akm in akms:
				retval += aakms.get(akm.suite) if not retval else ("/"+akms.get(akm.suite))

		return retval

	def toadd(self, bss):
		retval = True

		for ap in list(self.__ACCESSPOINTS.keys()):
			if bss == ap:
				retval = False
				break

		return retval

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
				'auth': auth,
			}

			self.__ACCESSPOINTS[ bssid ] = toappend
			print(self.__ACCESSPOINTS)

	def hopper(self):
		while True:
			ch = random.choice(self.channels)
			subprocess.call(['iwconfig', self.interface, 'channel', ch])

			time.sleep(0.5)

	def sniff(self):
		t = threading.Thread(target=self.hopper)
		t.daemon = True
		t.start()

		sniff(iface=self.interface, prn=self.filter)
		sys.stdout.write("\r")