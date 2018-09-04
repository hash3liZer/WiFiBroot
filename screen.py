from utils import tabulate
from scapy.utils import hexdump
import curses
import time
import string
import binascii

class Display:

	shifter_break = False
	Shifter_stopped = False
	__WiFiAP = []

	# Crackinig Variables

	_count_ = 0

	def __init__(self, verbosity):
		self.screen = curses.initscr()
		curses.noecho()
		curses.cbreak()
		self.screen.keypad(1)
		self.screen.scrollok(True)
		self.verbose = verbosity

	def __del__(self):
		self.screen.keypad(0)
		curses.nocbreak()
		curses.echo()
		curses.endwin()

	def destroy(self):
		''' Explicit Definition for destroying the object '''

		self.screen.keypad(0)
		curses.nocbreak()
		curses.echo()
		curses.endwin()

	def c_time(self):
		return time.asctime(time.localtime(time.time()))

	def cch(self, ch):
		ch = str(ch)
		if len(ch) == 1:
			ch = '0'+ch
		return ch

	def Shifter(self, sniffer, iface_instance):

		if self.verbose:
			__HEADERS = ['NO', 'ESSID', 'PWR', 'ENC', 'CIPHER', 'AUTH', 'CH', 'BSSID', 'VENDOR']
		else:
			__HEADERS = ['NO', 'ESSID', 'PWR', 'ENC', 'CIPHER', 'AUTH', 'CH', 'BSSID']

		while not self.shifter_break:
			tabulator__, __sig_LIST, self.__WiFiAP, __sig_FOUND = [], [], [], []

			for ap in sniffer.results():
				__sig_LIST.append(ap['pwr'])

			__sig_LIST = sorted(__sig_LIST, reverse=True)
			count = 1

			for sig in __sig_LIST:
				for ap in sniffer.results():
					if ap['pwr'] == sig and not ap['bssid'] in __sig_FOUND:
						__sig_FOUND.append(ap['bssid'])
						ap['count'] = count
						count += 1
						self.__WiFiAP.append(ap)

			for ap in self.__WiFiAP:
				if self.verbose:
					tabulator__.append([ap['count'], ap['essid'], ap['pwr'], ap['auth'], ap['cipher'], \
							ap['psk'], ap['channel'], ap['bssid'].upper(), ap['vendor']])
				else:
					tabulator__.append([ap['count'], ap['essid'], ap['pwr'], ap['auth'], ap['cipher'], \
							ap['psk'], ap['channel'], ap['bssid'].upper()])

			self.screen.addstr(0, 0, "[%s] Channel [%s] Time Elapsed [%d] Networks Found"\
									% (self.cch(iface_instance.cch), self.c_time(), len(tabulator__)))
			self.screen.addstr(1, 0, "\n"+tabulate(tabulator__, headers=__HEADERS)+"\n")
			self.screen.refresh()
			
		self.Shifter_stopped = not False

	def clear(self):
		self.screen.clear()

	def get_size(self):
		try:
			from backports.shutil_get_terminal_size import get_terminal_size
			return get_terminal_size().columns
		except:
			return None

