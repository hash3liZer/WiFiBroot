#!/usr/bin/python

import os
import re
import sys
import argparse
import subprocess
from pull import PULL

class PARSER:

	def __init__(self, prs):
		# Mode Detector
		self.mode      = self.mode(prs.mode)

		# Filters
		self.world     = prs.world
		self.interface = self.interface(prs.interface)
		self.channels  = self.channels(prs.channels)
		self.essids    = self.form_essids(prs.essids)
		self.aps       = self.form_macs(prs.aps)
		self.stations  = self.form_macs(prs.stations)
		self.filters   = self.form_macs(prs.filters)

		if self.mode == 0:
			self.wordlist = self.wordlist(prs.wordlist)

	def mode(self, md):
		amodes = (0, 1, 2)
		if md in amodes:
			return md
		else:
			pull.halt("Invalid Mode Supplied. ", True, pull.RED)

	def wordlist(self, wd):
		if wd:

		else:


	def channels(self, ch):
		retval = list(range(1,15)) if self.world else list(range(1,12))
		if ch:
			if ch in retval:
				return [ch]
			else:
				pull.halt("Invalid Channel Given.", True, pull.RED)
		else:
			return retval

	def form_essids(self, essids):
		retval = []
		if essids:
			toloop = essids.split(",")
			for essid in toloop:
				if not re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", essid):
					retval.append(essid)

		return retval

	def form_macs(self, bssids):
		retval = []
		if bssids:
			toloop = bssids.split(",")
			for bssid in toloop:
				if re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", bssid):
					retval.append(bssid.lower())

		return retval

	def interface(self, iface):
		def getNICnames():
			ifaces = []
			dev = open('/proc/net/dev', 'r')
			data = dev.read()
			for n in re.findall('[a-zA-Z0-9]+:', data):
				ifaces.append(n.rstrip(":"))
			return ifaces

		def confirmMon(iface):
			co = subprocess.Popen(['iwconfig', iface], stdout=subprocess.PIPE)
			data = co.communicate()[0].decode()
			card = re.findall('Mode:[A-Za-z]+', data)[0]	
			if "Monitor" in card:
				return True
			else:
				return False

		if iface:
			ifaces = getNICnames()
			if iface in ifaces:
				if confirmMon(iface):
					return iface
				else:
					pull.halt("Interface Not In Monitor Mode [%s]" % (pull.RED + iface + pull.END), True, pull.RED)
			else:
				pull.halt("Interface Not Found. [%s]" % (pull.RED + iface + pull.END), True, pull.RED)
		else:
			pull.halt("Interface Not Provided. Specify an Interface!", True, pull.RED)

def main():
	parser = argparse.ArgumentParser(add_help=True)

	# Interface Argument
	parser.add_argument('-i', '--interface'    , dest="interface", default="", type=str)

	# Filterss
	parser.add_argument('-c', '--channel'      , dest="channels" , default=0 , type=int)
	parser.add_argument('-e', '--essids'       , dest="essids"   , default="", type=str)
	parser.add_argument('-a', '--accesspoints' , dest="aps"      , default="", type=str)
	parser.add_argument('-s', '--stations'     , dest="stations" , default="", type=str)
	parser.add_argument('-f', '--filters'      , dest="filters"  , default="", type=str)
	parser.add_argument(      '--world'        , dest="world"    , default=0 , type=int)

	# Mode
	parser.add_argument('-m', '--mode'         , dest="mode"     , default=0 , type=int)

	# Mode A
	parser.add_argument('-w', '--wordlist'     , dest="wordlist" , default="", type=str)

	options = parser.parse_args()
	parser  = PARSER(options)

if __name__ == "__main__":
	pull = PULL()
	main()