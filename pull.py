import os
import sys
import random


__help__ = """
Usage: python3 wifibroot.py -m [mode] [arguments]

Modes:
    #     Description                                 Value
    01    Capture 4-way handshake by sending Deauth
          frames                                        1
    02    Capture PMKID by forcing AP to transmit 
          EAPOL.                                        2

Use -h, --help after -m, --mode to get help on modes. 
"""

__helpa__ = """
Usage: python3 wifibroot.py -m 1 --interface [Interface] [arguments]

Mode:
    01   Capture 4-way handshake by sending Deauth
         frames 

Manual:
    Args               Description                         Required
    -h, --help         Print this Manual                     NO
    -m, --mode         Mode, Must be 1                       YES
    -i, --interface    Monitor Mode Interface to Use         YES
    -c, --channel      Specific Channel to listen on.        NO
                       Default: All
    -e, --essids       Essids to Scan For. (Comma-seperate)  NO
                       Default: All
    -a, --accesspoints Bssids to Scan For. (Comma-seperate)  NO
                       Default: All
    -s, --stations     Specific Stations to target.          NO
                       Default: All
    -f, --filters      Bssids to Filter. (Comma-seperate)    NO
                       Default: All
    -o, --output       Filename to Store Packets             YES
                       Default: None
    -p, --packets      Number of Deauthentication packets
                       to send. Default: 25                  NO
        --code         Deauthentication Code to Send
                       Default: 7                            NO
        --delay        Delay Between Packets
                       Default: 0.01                         NO
        --world        Scan on all 14 channels               NO
                       Default: False
        --verbose      Shows Device Manufacturers while
                       Scanning.                             NO
"""

__helpb__ = """
Usage: python3 wifibroot.py -m 2 --interface [Interface] [arguments]

Mode:
    02   Force AP to transmit EAPOL and capture PMKID

Manual:
    Args               Description                         Required
    -h, --help         Print this Manual                     NO
    -m, --mode         Mode, Must be 1                       YES
    -i, --interface    Monitor Mode Interface to Use         YES
    -c, --channel      Specific Channel to listen on.        NO
                       Default: All
    -e, --essids       Essids to Scan For. (Comma-seperate)  NO
                       Default: All
    -a, --accesspoints Bssids to Scan For. (Comma-seperate)  NO
                       Default: All
    -s, --stations     Specific Stations to target.          NO
                       Default: All
    -f, --filters      Bssids to Filter. (Comma-seperate)    NO
                       Default: All
        --pmkid        Filename to PMKID Capture             NO
                       Default: None
        --world        Scan on all 14 channels               NO
                       Default: False
        --pkts-auth    Number of Authentication Packets to
                       Send in one loop. Default: 1          NO
        --pkts-asso    Number of Association Packets to
                       Send in one loop. Default: 1          NO
        --delay        Delay for Authentication and
                       Association Packets. Default: 0.01    NO
        --verbose      Shows Device Manufacturers while
                       Scanning.                             NO
"""

class PULL:

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

	MIXTURE = {
		'WHITE': '\033[0m',
		'PURPLE': '\033[95m',
		'CYAN': '\033[96m',
		'DARKCYAN': '\033[36m',
		'BLUE': '\033[94m',
		'GREEN': '\033[92m',
		'YELLOW': '\033[93m',
		'RED': '\033[91m',
		'BOLD': '\033[1m',
		'UNDERLINE': '\033[4m',
		'END': '\033[0m',
		'LINEUP': '\033[F'
	}

	VACANT = {
		'WHITE': '',
		'PURPLE': '',
		'CYAN': '',
		'DARKCYAN': '',
		'BLUE': '',
		'GREEN': '',
		'YELLOW': '',
		'RED': '',
		'BOLD': '',
		'UNDERLINE': '',
		'END': '',
		'LINEUP': ''
	}

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
		self.MIXTURE = {
			'WHITE': '',
			'PURPLE': '',
			'CYAN': '',
			'DARKCYAN': '',
			'BLUE': '',
			'GREEN': '',
			'YELLOW': '',
			'RED': '',
			'BOLD': '',
			'UNDERLINE': '',
			'END': '',
			'LINEUP': ''
		}

		for key in list(self.MIXTURE.items()):
			self.MIXTURE[ key ] = ''

	def linebreak(self, howmany=1):
		for n in range(0, howmany):
			sys.stdout.write( "\n" )

	def write(self, statement):
		sys.stdout.write(
			statement
		)

	def print(self, sig, statement, *colors):
		cc = ''
		cc = "".join([color for color in colors])
		print("{mix}[{sig}]{end} {statement}".format(
				sig=sig,
				mix=cc,
				end=self.END,
				statement=statement
			))

	def indent(self, sig, statement, *colors):
		cc = ''
		cc = "".join([color for color in colors])
		print("    {mix}{sig}{end} {statement}".format(
				sig=sig,
				mix=cc,
				end=self.END,
				statement=statement
			))

	def verbose(self, sig, statement, verbose, *colors):
		if verbose:
			cc = ''
			cc = "".join([color for color in colors])
			print("{mix}[{sig}]{end} {statement}".format(
					sig=sig,
					mix=cc,
					end=self.END,
					statement=statement
				))

	def input(self, sig, statement, validation=(), *colors):
		cc = ''
		cc = "".join([color for color in colors])
		value = input("{mix}[{sig}]{end} {statement}".format(
					sig=sig,
					mix=cc,
					end=self.END,
					statement=statement
				))
		if value:
			if validation:
				if value in validation:
					return value.lower()
				else:
					self.print("!", "Something Not Valid here. Enter a Valid Value.", self.RED)
					value = self.input(sig, statement, validation, cc)
			else:
				return value
		else:
			self.print("!", "Something Not Valid here. Enter a Valid Value.", self.RED)
			value = self.input(statement, validation, cc)			

		return value

	def halt(self, statement, exit, *colors):
		cc = ''
		cc = "".join([color for color in colors])
		print("{mix}[~]{end} {statement}".format(
				mix=cc,
				end=self.END,
				statement=statement
			))
		if exit:
			sys.exit(-1)

	def get_mac(self, bss):
		retval = ''

		if os.path.isfile(os.path.join(os.getcwd(), 'maclist', 'macs.txt')):
			lines = open(os.path.join(os.getcwd(), 'maclist', 'macs.txt'))
			for line in lines:
				line = line.split( " ~ " )
				if bss.lower().startswith(line[0].lower()[:8]):
					retval = line[1].split(" ")[0].upper()

		return retval

	def help(self):
		sys.exit(
				__help__
			)

	def helpa(self):
		sys.exit(
				__helpa__
		)

	def helpb(self):
		sys.exit(
				__helpb__
		)

	def logo(self):
		color = random.choice([
				self.DARKCYAN,
				self.RED,
				self.YELLOW,
			])
		print(
			"{mcolor}{bcolor}{body}{ecolor}\n\t\t{amcolor}@hash3liZer v1.0{aecolor}\n".format(
					mcolor=color,
					bcolor=self.BOLD,
					body=__logo__,
					ecolor=self.END,
					amcolor=self.BOLD,
					aecolor=self.END
				)
			)