# Shifter.py

from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import RadioTap
from scapy.sendrecv import sniff
from scapy.config import conf
from scapy.utils import PcapWriter
from scapy.utils import rdpcap
from utils import org
import re
try:
	from scapy.layers.dot11 import EAPOL
except ImportError:
	from scapy.layers.eap import EAPOL
try:
	long
	unicode
except NameError:
	long = int
	unicode = str

class Shifter:

	bss_counter = []
	clients = []
	cells = []
	p_BEACON = 0
	__ALSA_CLIENTS = {}
	__BLACKLIST = ('ffffffffffff')

	def __init__(self, iface, bss, ess, verbose):
		self.iface = iface
		conf.iface = self.iface
		self.ess = ess
		self.bss = bss
		self.verbose = verbose

	def check_cipher_48(self, layer):
		compound = layer.info
		u_cipher = ''
		p_cipher = ''
		psk = ''
		comp_sections = compound.split('\x00\x00')[1:]
		u_ciphers = {'\x0f\xac\x00': 'GROUP',
					  '\x0f\xac\x01': 'WEP',
					  '\x0f\xac\x02': 'TKIP',
					  '\x0f\xac\x04': 'CCMP',
					  '\x0f\xac\x05': 'WEP'}
		p_ciphers = {'\x0f\xac\x00': 'GROUP',
					  '\x0f\xac\x01': 'WEP',
					  '\x0f\xac\x02\x00\x0f\xac\x04': 'TKIP/CCMP',
					  '\x0f\xac\x04\x00\x0f\xac\x02': 'CCMP/TKIP',
					  '\x0f\xac\x02': 'TKIP',
					  '\x0f\xac\x04': 'CCMP',
					  '\x0f\xac\x05': 'WEP'}
		psk_keys = {'\x0f\xac\x01': 'MGT',
					'\x0f\xac\x02': 'PSK'}
		for key, value in u_ciphers.items():
			if comp_sections[0].startswith(key):
				u_cipher = value
		for key, value in p_ciphers.items():
			if comp_sections[1].startswith(key):
				p_cipher = value
		for key, value in psk_keys.items():
			if comp_sections[2].startswith(key):
				psk = value
		return [u_cipher, psk]

	def check_cipher_221(self, layer):
		compound = layer.info
		u_cipher = ''
		p_cipher = ''
		psk = ''
		comp_sections = compound.split('\x00\x00')[1:]
		u_ciphers = {'P\xf2\x00': 'GROUP',
					  'P\xf2\x01': 'WEP',
					  'P\xf2\x02': 'TKIP',
					  'P\xf2\x04': 'CCMP',
					  'P\xf2\x05': 'WEP'}
		p_ciphers = {'P\xf2\x00': 'GROUP',
					  'P\xf2\x01': 'WEP',
					  'P\xf2\x02\x00P\xf2\x04': 'TKIP/CCMP',
					  'P\xf2\x04\x00P\xf2\x02': 'CCMP/TKIP',
					  'P\xf2\x02': 'TKIP',
					  'P\xf2\x04': 'CCMP',
					  'P\xf2\x05': 'WEP'}
		psk_keys = {'P\xf2\x01': 'MGT',
					'P\xf2\x02': 'PSK'}
		for key, value in u_ciphers.items():
			if comp_sections[0].startswith(key):
				u_cipher = value
		for key, value in p_ciphers.items():
			if comp_sections[1].startswith(key):
				p_cipher = value
		for key, value in psk_keys.items():
			if comp_sections[2].startswith(key):
				psk = value
		return [u_cipher, psk]

	def enc_shift(self, cap, ELTLAYERS):
		layer_data__ = {'essid': '', 'channel': 0, 'auth': '', 'cipher': '', 'psk': ''}
		for dig in range(20):
			try:
				if ELTLAYERS[dig].ID == 0:
					layer_data__['essid'] = ELTLAYERS[dig].info  # ESSID
				elif ELTLAYERS[dig].ID == 3 and ELTLAYERS[dig].len == 1:
					layer_data__['channel'] = ord(ELTLAYERS[dig].info) # Channel
				elif ELTLAYERS[dig].ID == 48:  # Encryption
					layer_data__['auth'] = 'WPA2'
					cipher, psk = self.check_cipher_48( ELTLAYERS[dig])
					layer_data__['cipher'], layer_data__['psk'] = cipher, psk
				elif ELTLAYERS[dig].ID == 221 and ELTLAYERS[dig].info.startswith("\x00P\xf2\x01\x01\x00"):
					if not layer_data__['auth']:
						layer_data__['auth'] = 'WPA'
					else:
						layer_data__['auth'] += '/WPA'
					cipher, psk = self.check_cipher_221( ELTLAYERS[dig] )
					layer_data__['cipher'], layer_data__['psk'] = cipher, psk
				else:
					pass
			except IndexError:
				break
		if not layer_data__['auth']:
			if 'privacy' in cap:
				layer_data__['auth'] = 'WEP'
			else:
				layer_data__['auth'] = 'OPEN'
		return layer_data__

	def dBM_sig(self, pkt):
		if pkt.haslayer(RadioTap):
			extra = pkt.notdecoded
			dbm_sig = '?'
			for p in extra:
				if -(256-ord(p)) > -90 and -(256-ord(p)) < -20:
					dbm_sig = -(256-ord(p))
					break
			return dbm_sig

	def filtertify(self, bssid, __data):
		if self.bss != None and self.ess != None:
			return self.bss == bssid and self.ess == __data['essid']
		elif self.bss != None:
			return self.bss == bssid
		elif self.ess != None:
			return self.ess == __data['essid']
		else:
			return True

	def clients_garbage(self, pkt):
		if pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == long(2) and not pkt.haslayer(EAPOL):
			_sn = pkt.getlayer(Dot11).addr2
			_rc = pkt.getlayer(Dot11).addr1

			_tgt = None

			if _sn in self.bss_counter:
				_tgt, _ap = _rc, _sn
			elif _rc in self.bss_counter:
				_tgt, _ap = _sn, _rc

			if _tgt and _tgt not in self.clients:
				for cell in self.cells:
					for _key, _val in cell.items():
						if _key == 'bssid' and _val == _ap:
							if not (_tgt.replace(':','').lower() in self.__BLACKLIST):
								cell['clients'] += 1; self.clients.append(_tgt)
								self.__ALSA_CLIENTS[_val].append( (_tgt, self.dBM_sig(pkt)) )

	def beac_shift(self, pkt):
		if pkt.haslayer(Dot11Beacon):
			bssid = pkt.getlayer(Dot11).addr2
			cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split('+')
			ELTLAYERS = pkt.getlayer(Dot11Elt)
			if bssid not in self.bss_counter:
				self.bss_counter.append(bssid)
				layer_data__ = self.enc_shift(cap, ELTLAYERS)
				s_or_n = self.filtertify(bssid.lower(), layer_data__)
				if s_or_n:
					self.cells.append({'essid': unicode(layer_data__['essid']), 'bssid': unicode(bssid), 'channel': unicode(layer_data__['channel']), 'auth': unicode(layer_data__['auth']), \
						'cipher': unicode(layer_data__['cipher']), 'psk': unicode(layer_data__['psk']), 'pwr': self.dBM_sig(pkt), 'beacon': pkt, 'vendor': unicode(org(bssid).org), 'clients': 0})
					self.__ALSA_CLIENTS[bssid] = []
			else:
				for ap in self.cells:
					if ap['bssid'] == bssid:
						ap['pwr'] = self.dBM_sig(pkt)


	def ssid_shift(self, pkt):
		self.beac_shift(pkt)
		self.clients_garbage(pkt)

	def results(self):
		return self.cells

	def run(self):
		pkts = sniff(iface=self.iface, prn=self.ssid_shift)

