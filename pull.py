from __future__ import print_function

import sys
import os
import random

try:
	raw_input
except NameError:
	raw_input = input

__log__ = r'''%s
 _        ___  ___ ___  ___   ___
 \\  _ /\*\___*\__\\__\/   \ /   \\___
  \  \\  \\\   \\__\\ /\  ) \\  ) \\  \
   \__\\__\\\   \\__\\ \\__ / \___/ \__\
%s
          %sv1.0. Coded by @hash3liZer.%s
'''

__mode__='''
Syntax:
    $ python wifibroot.py [--mode [modes]] [--options]
    $ python wifibroot.py --mode 2 -i wlan1mon --verbose -d /path/to/list -w pmkid.txt

Modes:
    #     Description                                 Value
    01    Capture 4-way handshake and crack MIC code    1
    02    Captures and Crack PMKID (PMKID Attack)       2
    03    Perform Manaul cracking on available
          capture types. See --list-types               3
    04    Deauthentication. Disconnect two stations
          and jam the traffic.                          4

Use -h, --help after -m, --mode to get help on modes.
'''

__1help__='''
Mode:
   01      Capture 4-way handshake and crack MIC code    1

Options:
   Args               Description                      Required
   -h, --help         Show this help manual              NO
   -i, --interface    Monitor Interface to use           YES
   -v, --verbose      Turn off Verbose mode.             NO
   -t, --timeout      Time Delay between two deauth
                      requests.                          NO
   -d, --dictionary   Dictionary for Cracking            YES
   -w, --write        Write Captured handshake to
                      a seperate file                    NO
       --deauth       Number of Deauthentication
                      frames to send                     NO

Filters:
   -e, --essid         ESSID of listening network
   -b, --bssid         BSSID of target network.
   -c, --channel       Channel interface should be listening
                       on. Default: ALL
'''

__2help__='''
Mode:
   02      Captures and Crack PMKID (PMKID Attack)       1

Options:
   Args               Description                      Required
   -h, --help         Show this help manual              NO
   -i, --interface    Monitor Interface to use           YES
   -v, --verbose      Turn off Verbose mode.             NO
   -d, --dictionary   Dictionary for Cracking            YES
   -w, --write        Write Captured handshake to
                      a seperate file                    NO

Filters:
   -e, --essid         ESSID of listening network
   -b, --bssid         BSSID of target network.
   -c, --channel       Channel interface should be listening
                       on. Default: ALL
'''

__3help__='''
Mode:
   03    Perform Manaul cracking on available capture
         types. See --list-types                         3

Options:
   Args               Description                      Required
   -h, --help         Show this help manual              NO
       --list-types   List available cracking types      NO
       --type         Type of capture to crack           YES
   -v, --verbose      Turn off Verbose mode.             NO
   -d, --dictionary   Dictionary for Cracking            YES
   -e, --essid        ESSID of target network.
                      Only for HANDSHAKE Type            YES
   -r, --read         Captured file to crack             YES
'''

__4help__='''
Mode:
    04   Deauthentication. Disconnect two stations
         and jam the traffic.                            4

Options:
    Args              Description                      Required
    -h, --help        Show this help manual              NO
    -i, --interface   Monitor Mode Interface to use      YES
    -0, --count       Number of Deauthentication
                      frames to send. '0' specifies
                      unlimited frames                   YES
        --ap          Access Point MAC Address           NO
        --client      STA (Station) MAC Address          NO
'''

__list__='''
Types:
    #         Type            Value
    1         HANDSHAKE       handshake
    2         PMKID           pmkid
'''


class Pully:

	WHITE = '\033[0m'
	PURPLE = '\033[95m'
	CYAN = '\033[96m'
	DARKCYAN = '\033[36m'
	BLUE = '\033[94m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	END = '\033[0m'
	LINEUP = '\033[F'

	def __init__(self):
		if not self.support_colors:
			self.win_colors()

	def support_colors(self):
		plat = sys.platform
		supported_platform = plat != 'Pocket PC' and (plat != 'win32' or \
														'ANSICON' in os.environ)
		is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
		if not supported_platform or not is_a_tty:
			return False
		return True


	def win_colors(self):
		self.WHITE = ''
		self.PURPLE = ''
		self.CYAN = ''
		self.DARKCYAN = ''
		self.BLUE = ''
		self.GREEN = ''
		self.YELLOW = ''
		self.RED = ''
		self.BOLD = ''
		self.UNDERLINE = ''
		self.END = ''
		self.LINEUP = ''

	def info(self, statement, *args, **kwargs):
		print("%s[*]%s %s" % (self.BOLD+self.YELLOW, self.END, statement))
		return

	def error(self, statement, *args, **kwargs):
		print("%s[!]%s %s" % (self.BOLD+self.RED, self.END, statement))
		return

	def up(self, statement, *args, **kwargs):
		print("%s[^]%s %s" % (self.BOLD+self.BLUE, self.END, statement))
		return

	def use(self, statement, *args, **kwargs):
		print("%s[+]%s %s" % (self.BOLD+self.GREEN, self.END, statement))
		return

	def question(self, statement, *args, **kwargs):
		q = raw_input("%s[?]%s %s" % (self.BOLD+self.PURPLE, self.END, statement))
		return q

	def delete(self, statement, *args, **kwargs):
		print("%s[#]%s %s" % (self.BOLD+self.CYAN, self.END, statement))
		return

	def special(self, statement, *args, **kwargs):
		print("%s[~]%s %s" % (self.BOLD+self.RED, self.END, statement))

	def spacer(self, statement, *args, **kwargs):
		print("    %s" % (statement))

	def linebreak(self):
		print("\n")
		return

	def right(self, statement, *args, **kwargs):
		print("%s[>]%s %s" % (self.BOLD+self.DARKCYAN, self.END, statement))

	def lineup(self, *args, **kwargs):
		sys.stdout.write(self.LINEUP)

	def random_picker(self):
		seq = (self.RED, self.GREEN, self.YELLOW, self.BLUE)
		return random.choice(seq)

	def logo(self):
		print(__log__ % (self.BOLD+self.random_picker(), self.END, self.BOLD, self.END))

	def help(self, _m):
		if _m == 1:
			print(__1help__)
		elif _m == 2:
			print(__2help__)
		elif _m == 3:
			print(__3help__)
		elif _m == 4:
			print(__4help__)

	def modes(self):
		print(__mode__)

	def listTypes(self):
		print(__list__)