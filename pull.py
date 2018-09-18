
import sys
import os
import random

__log__ = r'''%s
 _        ___  ___ ___  ___   ___
 \\  _ /\*\___*\__\\__\/   \ /   \\___
  \  \\  \\\   \\__\\ /\  ) \\  ) \\  \
   \__\\__\\\   \\__\\ \\__ / \___/ \__\
%s 
          %sv1.0. Coded by @hash3liZer.%s
'''

__help__ ='''
WiFi Modes:
    #     Description                                 Value
   01     Capture 4-way handshake and crack MIC code    1
   02     Capture and Crack PMKID                       2

All Options:
    -h, --help          Show this help Manual. 
    -i, --interface     Monitor Interface to use
    -m, --mode          Mode to use, see the list available    
    -v, --verbose       Verbose Mode. Print hashes too. 
    -t, --timeout       Timeout for clients detection.
                        Default: 15
    -p, --passwords     Comma Seperated list of passwords
                        instead of dictionary
    -d, --dictionary    Use this dictionary instead of
                        default one.
    -w, --write         Write Captured Data to a File
        --deauth        Number of deauthentication packets
                        to send. Default: 32
        --handshake     Handshake to use instead of
                        performing dissociation

Filters: 
    -e, --essid         ESSID of listening network
    -b, --bssid         BSSID of target network.
    -c, --channel       Channel interface should be listening
                        on. Default: ALL

[Mode Specific Options]
    [Mode 1]
        -m, --mode      Value: 1
        -t, --timeout   Timeout for gap between deauthentication
                        packets
            --deauth    Number of deauthentication packets
                        to send
            --handshake     Handshake to use instead of
                        performing dissociation
        -w, --write     Write handshake to a file

    [Mode 2]
        -m, --mode      Value: 2
        -w, --write     Write pmkid capture in a seperate file.
                        Can then be used with hashcat
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
		print "%s[*]%s %s" % (self.BOLD+self.YELLOW, self.END, statement)
		return

	def error(self, statement, *args, **kwargs):
		print "%s[!]%s %s" % (self.BOLD+self.RED, self.END, statement)
		return

	def up(self, statement, *args, **kwargs):
		print "%s[^]%s %s" % (self.BOLD+self.BLUE, self.END, statement)
		return

	def use(self, statement, *args, **kwargs):
		print "%s[$]%s %s" % (self.BOLD+self.GREEN, self.END, statement)
		return

	def question(self, statement, *args, **kwargs):
		q = raw_input("%s[?]%s %s" % (self.BOLD+self.PURPLE, self.END, statement))
		return q

	def delete(self, statement, *args, **kwargs):
		print "%s[#]%s %s" % (self.BOLD+self.CYAN, self.END, statement)
		return

	def special(self, statement, *args, **kwargs):
		print "%s[~]%s %s" % (self.BOLD+self.RED, self.END, statement)

	def spacer(self, statement, *args, **kwargs):
		print "    %s" % (statement)

	def linebreak(self):
		print "\n"
		return

	def right(self, statement, *args, **kwargs):
		print "%s[>]%s %s" % (self.BOLD+self.DARKCYAN, self.END, statement)

	def lineup(self, *args, **kwargs):
		sys.stdout.write(self.LINEUP)

	def random_picker(self):
		seq = (self.RED, self.GREEN, self.YELLOW, self.BLUE)
		return random.choice(seq)

	def logo(self):
		print __log__ % (self.BOLD+self.random_picker(), self.END, self.BOLD, self.END)

	def help(self):
		print __help__