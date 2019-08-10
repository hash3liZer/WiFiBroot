from __future__ import print_function
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Raw
from scapy.layers.dot11 import Dot11Auth
from scapy.layers.dot11 import Dot11AssoReq
from scapy.layers.dot11 import Dot11AssoResp
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11Elt
from scapy.utils import rdpcap
from pbkdf2 import PBKDF2
from utils import org
from scapy.arch import get_if_raw_hwaddr
try:
	from scapy.layers.eap import EAPOL
except:
	from scapy.layers.dot11 import EAPOL
import threading
import time
import binascii
import hmac
import hashlib
import string
import sys
import sha

try:
	xrange
except NameError:
	xrange = range

class CAPTURE_HAND:

	__POLS = [0, 0, 0, 0]
	__POL = False
	__NULL_ = "\x00"

	def __init__(self, pull, _file, _dict, _ess, _v):
		self.verbose = _v
		self.pull = pull
		self.essid = self.get_ess(_ess)
		self.file = _file
		self.passes = self.passer(_dict)
		self.pkts = self.opener(_file)
		self.bssid = ''
		self.cl = ''

	def opener(self, _file):
		self.pull.up("Reading File: %s[%s]%s" % (self.pull.BLUE, _file, self.pull.END))
		return rdpcap(_file)

	def get_ess(self, _ess):
		if _ess:
			return _ess
		else:
			self.pull.error("SSID no Specified. Specify -e, --essid option for handshake")
			sys.exit()

	def passer(self, _dict):
		file_ = open(_dict, 'r')
		_lines = file_.read().splitlines()
		_liner = []
		for l in _lines:
			_liner.append(l.rstrip("\n"))
		return _liner

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

	def verify(self):
		self.pull.up("Validating Received Captures..."); time.sleep(2)
		for pkt in self.pkts:
			self.check(pkt)
			if 0 not in self.__POLS:
				self.__POL = True; break
		if self.__POL:
			if self.verbose:
				self.pull.info("EAPOL %s (%s) %s<>%s %s (%s) %s[RECEIVED]%s" % (self.bssid.replace(':','').upper(), self.pull.DARKCYAN+org(self.bssid).org+self.pull.END, self.pull.RED, self.pull.END, \
															self.cl.replace(':','').upper(), self.pull.DARKCYAN+org(self.cl).org+self.pull.END, self.pull.YELLOW, self.pull.END))
			else:
				self.pull.info("EAPOL %s %s<>%s %s %s[RECEIVED]%s" % (self.bssid.replace(':','').upper(), self.pull.RED, self.pull.END, \
															self.cl.replace(':','').upper(), self.pull.YELLOW, self.pull.END))
			return True
		else:
			return False

	def check(self, pkt):
		fNONCE = "0000000000000000000000000000000000000000000000000000000000000000"
		fMIC = "00000000000000000000000000000000"

		if pkt.haslayer(EAPOL):
			__sn = pkt[Dot11].addr2
			__rc = pkt[Dot11].addr1
			to_DS = pkt.getlayer(Dot11).FCfield & 0x1 !=0
			from_DS = pkt.getlayer(Dot11).FCfield & 0x2 !=0

			if from_DS == True:
				nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
				mic = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
				if nonce != fNONCE and mic == fMIC:
					self.bssid = __sn; self.cl = __rc
					self.__POLS[0] = pkt
				elif __sn == self.bssid and __rc == self.cl and nonce != fNONCE and mic != fMIC:
					self.__POLS[2] = pkt
			elif to_DS == True:
				nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
				mic = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
				if __sn == self.cl and __rc == self.bssid and nonce != fNONCE and mic != fMIC:
					self.__POLS[1] = pkt
				elif __sn == self.cl and __rc == self.bssid and nonce == fNONCE and mic != fMIC:
					self.__POLS[3] = pkt

	def printing_pass(self, p_pass, c_pass):
		len_A, len_B = len(p_pass), len(c_pass)
		if len_A != 0:
			if len_A > len_B:
				return c_pass + ( " "*(len_A - len_B) )
			else:
				return c_pass
		else:
			return c_pass

	def print_back(self):
		time.sleep(2)
		if self.verbose:
			self.pull.up("Cracking %s (%s) %s<>%s %s (%s) %s[%s]%s" % (self.bssid.replace(':', '').upper(), self.pull.DARKCYAN+org(self.bssid).org+self.pull.END, self.pull.RED, self.pull.END, \
														self.cl.replace(':', '').upper(), self.pull.DARKCYAN+org(self.cl).org+self.pull.END, self.pull.GREEN, self.essid, self.pull.END))
		else:
			self.pull.up("Cracking %s %s<>%s %s %s[%s]%s" % (self.bssid.replace(':', '').upper(), self.pull.RED, self.pull.END, \
														self.cl.replace(':', '').upper(), self.pull.GREEN, self.essid, self.pull.END))

	def organize(self):
		self.print_back()
		self.bssid = binascii.a2b_hex(self.bssid.replace(':', '').lower())
		self.cl = binascii.a2b_hex(self.cl.replace(':', '').lower())
		self.aNONCE = binascii.a2b_hex(binascii.hexlify(self.__POLS[0].getlayer(Raw).load)[26:90])
		self.cNONCE = binascii.a2b_hex(binascii.hexlify(self.__POLS[1].getlayer(Raw).load)[26:90])
		self.key_data = min(self.bssid, self.cl) + max(self.bssid, self.cl) + min(self.aNONCE, self.cNONCE) + max(self.aNONCE, self.cNONCE)
		self.mic = binascii.hexlify(self.__POLS[1].getlayer(Raw).load)[154:186]
		self.version = chr(self.__POLS[1].getlayer(EAPOL).version)
		self.type = chr(self.__POLS[1].getlayer(EAPOL).type)
		self.len = chr(self.__POLS[1].getlayer(EAPOL).len)

		self.payload = binascii.a2b_hex(binascii.hexlify(self.version\
					+self.type\
					+self.__NULL_\
					+self.len\
					+binascii.a2b_hex(binascii.hexlify(self.__POLS[1].getlayer(Raw).load)[:154])\
					+self.__NULL_*16\
					+binascii.a2b_hex(binascii.hexlify(self.__POLS[1].getlayer(Raw).load)[186:])))

	def customPRF512(self, key, A, B):
		blen = 64
		i    = 0
		R    = ''
		while i<=((blen*8+159)/160):
			hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),sha)
			i+=1
			R = R+hmacsha1.digest()
		return R[:blen]

	def loop(self):
		last_pass__ = ''
		for _pass in self.passes:
			self.pull.up('Current Password: %s' % self.printing_pass(last_pass__, _pass)); last_pass__ = _pass
			_pmk = PBKDF2(_pass, self.essid, 4096).read(32)
			_ptk = self.customPRF512(_pmk, "Pairwise key expansion", self.key_data)
			_mic = hmac.new(_ptk[0:16], self.payload, hashlib.md5).hexdigest()
			_mic_ = hmac.new(_ptk[0:16], self.payload, hashlib.sha1).hexdigest()[:32]
			if self.mic == _mic or self.mic == _mic_:
				self.pull.use("CRACKED! Key Found %s[%s]%s" % (self.pull.GREEN, _pass, self.pull.END))
				self.pull.right("PMK =>"); print(self.hexdump(_pmk))
				self.pull.right("PTK =>"); print(self.hexdump(_ptk))
				self.pull.right("MIC =>"); print(self.hexdump(_mic if self.mic == _mic else _mic_))
				return
			else:
				if _pass != self.passes[-1]:
					self.pull.lineup()

class CAPTURE_PMKID:

	__PMKIDS = []

	def __init__(self, pull, _file, _dict, _V):
		self.verbose = _V
		self.pull = pull
		self.file = _file
		self.passes = self.passer(_dict)
		self.lines = self.opener(_file)

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

	def opener(self, _file):
		_read = open(_file, 'r')
		_lines = _read.read().splitlines()
		_liner = []
		for l in _lines:
			_liner.append(l.rstrip('\n'))
		return _liner

	def verify(self):
		if len(self.lines) <= 0:
			return False
		else:
			for line in self.lines:
				if (len(line.split("*")) < 4) or (len(line.split("*")) > 4):
					return False
		return True

	def hwaddr(self, _addr):
		return ':'.join(_addr[i:i+2] for i in range(0,12,2))

	def passer(self, _dict):
		file_ = open(_dict, 'r')
		_lines = file_.read().splitlines()
		_liner = []
		for l in _lines:
			_liner.append(l.rstrip("\n"))
		return _liner

	def organize(self):
		self.pull.up("Validating Received Captures...")
		for l in self.lines:
			_eq_ = l.split("*")
			_pm, _ap, _cl, _ess = _eq_[0], _eq_[1], _eq_[2], _eq_[3]
			self.__PMKIDS.append( (_pm, _ap, _cl, _ess) )
			if self.verbose:
				self.pull.info("PMKID %s (%s) %s<>%s %s (%s) %s[RECEIVED]%s" % (_ap.upper(), self.pull.DARKCYAN+org(self.hwaddr(_ap)).org+self.pull.END, self.pull.RED, self.pull.END, \
															_cl.upper(), self.pull.DARKCYAN+org(self.hwaddr(_cl)).org+self.pull.END, self.pull.YELLOW, self.pull.END))
			else:
				self.pull.info("PMIID %s %s<>%s %s %s[RECEIVED]%s" % (_ap.upper(), self.pull.RED, self.pull.END, \
															_cl.upper(), self.pull.YELLOW, self.pull.END))
			time.sleep(1)

	def printing_pass(self, p_pass, c_pass):
		len_A, len_B = len(p_pass), len(c_pass)
		if len_A != 0:
			if len_A > len_B:
				return c_pass + ( " "*(len_A - len_B) )
			else:
				return c_pass
		else:
			return c_pass

	def loop(self):
		time.sleep(2)
		for (_pm, _ap, _cl, _ess) in self.__PMKIDS:
			if self.verbose:
				self.pull.up("Cracking %s (%s) %s<>%s %s (%s) %s[%s]%s" % (_ap.upper(), self.pull.DARKCYAN+org(self.hwaddr(_ap)).org+self.pull.END, self.pull.RED, self.pull.END, \
															_cl.upper(), self.pull.DARKCYAN+org(self.hwaddr(_cl)).org+self.pull.END, self.pull.GREEN, _pm.upper(), self.pull.END))
			else:
				self.pull.up("Cracking %s %s<>%s %s %s[%s]%s" % (_ap.upper(), self.pull.RED, self.pull.END, \
															_cl.upper(), self.pull.GREEN, _pm.upper(), self.pull.END))

			(_pass, _pmk) = self.crack(_pm, _ap, _cl, _ess)
			if _pass:
				self.pull.use("CRACKED! Key Found %s[%s]%s" % (self.pull.GREEN, _pass, self.pull.END))
				self.pull.right("PMK =>"); print(self.hexdump(_pmk))
				self.pull.right("PMKID =>"); print(self.hexdump(_pm))
			else:
				self.pull.error("Not Found! Password Not in Dictionary.")

	def crack(self, _pm_, _ap_, _cl_, _ess_):
		_last_pass = ''
		for _pass in self.passes:
			self.pull.up("Currently Checking: %s%s%s" % (self.pull.BLUE, self.printing_pass(_last_pass, _pass), self.pull.END))
			_last_pass = _pass
			_pmk = PBKDF2(_pass, binascii.unhexlify(_ess_), 4096).read(32)
			_ap = binascii.a2b_hex(_ap_)
			_cl = binascii.a2b_hex(_cl_)
			_pmk_string = "PMK Name"
			_hash = hmac.new(_pmk, _pmk_string+_ap+_cl, hashlib.sha1).hexdigest()[:32]
			if _hash == _pm_:
				return (_pass, _pmk)
			else:
				if _pass != self.passes[-1]:
					self.pull.lineup()
		return (None, None)

