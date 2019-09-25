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
from scapy.layers.dot11 import Dot11EltCountry
from scapy.layers.eap   import EAPOL

class SNIFFER:

	__ACCESSPOINTS = {}
	__EXCEPTIONS = [
		'ff:ff:ff:ff:ff:ff',
		'00:00:00:00:00:00',
		'33:33:00:',
		'33:33:ff:',
		'01:80:c2:00:00:00',
		'01:00:5e:'
	]

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

	def exception(self, sender, receiver):
		retval = False

		for exception in self.__EXCEPTIONS:
			if sender.startswith(exception) or receiver.startswith(exception):
				retval = True
				break

		return retval

	def filter_devices(self, sn, rc):
		retval = {
			'ap': '',
			'sta': ''
		}

		for bss in list(self.__ACCESSPOINTS.keys()):
			if sn == bss:
				retval[ 'ap'  ] = sn
				retval[ 'sta' ] = rc
			elif rc == bss:
				retval[ 'ap'  ] = rc
				retval[ 'sta' ] = sn 

		return retval

	def update_stations(self, ap, sta):
		if ap and sta:
			stations = self.__ACCESSPOINTS[ ap ][ 'stations' ]
			if sta not in stations:
				stations.append( sta )
				self.__ACCESSPOINTS[ ap ][ 'stations' ] = stations

	def update(self, toappend):
		bssid = toappend.get('bssid')
		essid = toappend.get('essid')
		channel = toappend.get('channel')
		power   = toappend.get('power')
		encryption = toappend.get('encryption')
		cipher  = toappend.get('cipher')
		auth    = toappend.get('auth')

		if bssid in list(self.__ACCESSPOINTS.keys()):
			self.__ACCESSPOINTS[ bssid ][ 'essid' ] = essid
			self.__ACCESSPOINTS[ bssid ][ 'channel' ] = channel
			self.__ACCESSPOINTS[ bssid ][ 'power' ] = power
			self.__ACCESSPOINTS[ bssid ][ 'encryption' ] = encryption
			self.__ACCESSPOINTS[ bssid ][ 'cipher' ] = cipher
			self.__ACCESSPOINTS[ bssid ][ 'auth' ] = auth
		else:
			self.__ACCESSPOINTS[ bssid ] = toappend

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
				'stations': []
			}

			self.update(toappend)
		else:
			sender = receiver = ""
			if pkt.haslayer(Dot11FCS) and pkt.getlayer(Dot11FCS).type == 2 and not pkt.haslayer(EAPOL):
				sender   = pkt.getlayer(Dot11FCS).addr2
				receiver = pkt.getlayer(Dot11FCS).addr1

			elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL):
				sender   = pkt.getlayer(Dot11).addr2
				receiver = pkt.getlayer(Dot11).addr1

			if sender and receiver:
				if not self.exception(sender, receiver):
					devices = self.filter_devices(sender, receiver)
					ap      = devices.get('ap')
					sta     = devices.get('sta')

					self.update_stations(ap, sta)

	def hopper(self):
		while True:
			ch = random.choice(self.channels)
			subprocess.call(['iwconfig', self.interface, 'channel', str(ch)])

			time.sleep(0.5)

	def sniff(self):
		t = threading.Thread(target=self.hopper)
		t.daemon = True
		t.start()

		sniff(iface=self.interface, prn=self.filter)
		sys.stdout.write("\r")