import sys
import os
import random

class org:

	def __init__(self, bssid=''):
		self.bssid = bssid
		self.org = self.findORG(self.bssid)

	def findORG(self, bssid):
		file__ = open(os.getcwd()+'/utils/macers.txt', 'r')
		for line in file__.readlines():
			if line.strip('\n').split(' ~ ')[0].lower() == bssid.lower()[0:9]+"xx:xx:xx":
				file__.close()
				return line.strip('\n').split(' ~ ')[1].split(' ')[0]
		file__.close()
		return 'unknown'

	def supports_color():	
		plat = sys.platform
		supported_platform = plat != 'Pocket PC' and (plat != 'win32' or 'ANSICON' in os.environ)
		# isatty is not always implemented, #6223.
		is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
		if not supported_platform or not is_a_tty:
			return False
		return True

	def randomness(self, _max, last_num):
		_to_return = last_num
		while _to_return == last_num:
			_to_return = random.randint(1, _max)
		return _to_return