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
from pbkdf2 import PBKDF2
from scapy.sendrecv import sniff
from scapy.sendrecv import sendp
from scapy.utils    import PcapWriter
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

class CRACK:

	__PKE    = "Pairwise key expansion"

	__FNONCE = "0000000000000000000000000000000000000000000000000000000000000000"
	__FMIC   = "00000000000000000000000000000000"

	__EAPOLS = {}

	def __init__(self, packets, passes, defer, store, essid):
		self.packets = packets
		self.passes  = passes
		self.defer   = defer
		self.store   = store
		self.essid   = essid

	def extract_elt_layer(self, identifier, pkt):
		layers = pkt.getlayer(Dot11Elt)
		retval = ''
		counter = 0

		try:
			while True:
				layer = layers[counter]
				if hasattr(layer, "ID") and layer.ID == identifier:
					retval = layer.info.decode("utf-8")
					break
				else:
					counter += 1
		except IndexError:
			pass

		return retval

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

	def count_shakes(self):
		counter = 0

		for ap in list(self.__EAPOLS.keys()):
			if len(self.__EAPOLS[ap]) == 4:
				counter += 1

		pull.print(
			"*",
			"Handshakes Captured --> Count [{count}]".format(
				count=pull.RED+str(counter)+pull.END
			),
			pull.YELLOW
		)

	def validate(self):
		for pkt in self.packets:
			if pkt.haslayer(EAPOL):
				retval = self.extract_sn_rc(pkt)
				sn     = retval[0]
				rc     = retval[1]

				retval = self.extract_ds(pkt)
				tds    = retval[0]
				fds    = retval[1]

				if fds == True:
					sta = rc
				elif tds == True:
					sta = sn

				if sta not in list(self.__EAPOLS.keys()):
					self.__EAPOLS[ sta ] = {}

				non   = binascii.hexlify(pkt.getlayer(Raw).load)[26:90].decode()
				mic   = binascii.hexlify(pkt.getlayer(Raw).load)[154:186].decode()

				if fds == True:
					if non != self.__FNONCE and mic == self.__FMIC:
						self.__EAPOLS[ rc ][ 1 ] = pkt
					elif non != self.__FNONCE and mic != self.__FMIC:
						self.__EAPOLS[ rc ][ 3 ] = pkt
				elif tds == True:
					if non != self.__FNONCE and mic != self.__FMIC:
						self.__EAPOLS[ sn ][ 2 ] = pkt
					elif non == self.__FNONCE and mic != self.__FMIC:
						self.__EAPOLS[ sn ][ 4 ] = pkt

			elif pkt.haslayer(Dot11Beacon):
				essid = self.extract_elt_layer(0, pkt)
				self.essid = essid

		for sta in list(self.__EAPOLS.keys()):
			if len(self.__EAPOLS[sta]) == 4:
				return True
		return False

	def calculate_hash(self, sta):
		pkts = self.__EAPOLS.get(sta)
		pkta = pkts.get(1)
		pktb = pkts.get(2)
		pktc = pkts.get(3)
		pktd = pkts.get(4)

		mic  = binascii.hexlify(pktb.getlayer(Raw).load)[154:186].decode()
		return mic

	def compute(self, password):
		pmk = PBKDF2(password, self.essid, 4096).read(32)
		#ptk = self.calculate_prf512(pmk, self.__PKE, )

	def engage(self):
		for sta in list(self.__EAPOLS.keys()):
			pull.print(
				"^",
				"Cracking TGT [{target}] Passes [{passes}]".format(
					target=pull.DARKCYAN+sta.upper()+pull.END,
					passes=pull.DARKCYAN+str(len(self.passes))+pull.END
				),
				pull.DARKCYAN
			)

			chash = self.calculate_hash( sta )

			for password in self.passes:
				cracked = self.compute(password)