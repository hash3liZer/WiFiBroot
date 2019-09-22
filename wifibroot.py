#!/usr/bin/python

import os
import re
import sys
import argparse
import subprocess
from pull import PULL
from wireless import SNIFFER

class SLAB_A:

	def __init__(self, prs):
		self.interface = prs.interface
		self.channels  = prs.channels
		self.essids    = prs.essids
		self.aps       = prs.aps
		self.stations  = prs.stations
		self.filters   = prs.filters
		self.output    = prs.output

	def sniff(self):
		sniffer = SNIFFER(
			self.interface,
			self.channels,
			self.essids,
			self.aps,
			self.stations,
			self.filters,
		)

		sniffer.sniff()

	def engage(self):
		pull.print(
			"*",
			"IFACE: [{iface}] CHANNELS [{channels}] OPUT [{output}]".format(
				iface=pull.DARKCYAN+self.interface+pull.END,
				channels=pull.DARKCYAN+str(len(self.channels))+pull.END,
				output=pull.DARKCYAN+"YES"+pull.END
			),
			pull.YELLOW
		)
		pull.print(
			"^",
			"Starting Sniffer. Press CTRL+C to Stop",
			pull.GREEN
		)

		self.sniff()


class HANDLER:

	def __init__(self, mode, prs):
		self.mode   = mode
		self.parser = prs

	def engage(self):
		if self.mode == 0:
			slab = SLAB_A(self.parser)
			slab.engage()

class PARSER:

	def __init__(self, prs):
		# Mode Detector
		self.mode      = self.mode(prs.mode)

		# Filters
		self.verbose   = prs.verbose
		self.world     = prs.world

		if self.mode == 0:
			self.interface = self.interface(prs.interface)
			self.channels  = self.channels(prs.channels)
			self.essids    = self.form_essids(prs.essids)
			self.aps       = self.form_macs(prs.aps)
			self.stations  = self.form_macs(prs.stations)
			self.filters   = self.form_macs(prs.filters)
			self.output    = self.output(prs.output)

	def mode(self, md):
		amodes = (0, 1, 2)
		if md in amodes:
			return md
		else:
			pull.halt("Invalid Mode Supplied. ", True, pull.RED)

	def output(self, fl):
		if fl:
			return open(fl, "w")
		else:
			pull.halt("Output Filename Not provided. Please supply an output", True, pull.RED)

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
	parser.add_argument(      '--verbose'      , dest="verbose"  , default=False, action="store_true")

	# Mode
	parser.add_argument('-m', '--mode'         , dest="mode"     , default=0 , type=int)

	# Mode A
	parser.add_argument('-o', '--output'       , dest="output"   , default="", type=str)

	options = parser.parse_args()
	parser  = PARSER(options)

	pull.print(
		"^",
		"Starting Broot Engine...",
		pull.DARKCYAN
	)

	handler = HANDLER(parser.mode, parser)
	handler.engage()

	pull.print(
		"<",
		"Done!",
		pull.DARKCYAN
	)

if __name__ == "__main__":
	pull = PULL()
	main()