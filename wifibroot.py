#!/usr/bin/python

import os
import re
import sys
import signal
import argparse
import subprocess
from pull import PULL
from tabulate import tabulate
from wireless import SNIFFER
from wireless import CAPTURE
from wireless import PMKID

DEFAULTHANDLER = signal.getsignal(signal.SIGINT)

class SIGNALER:

	def changer(self):
		signal.signal(signal.SIGINT, self.put_exit)

	def origanl(self):
		global DEFAULTHANDLER

		signal.signal(signal.SIGINT, DEFAULTHANDLER)

	def put_exit(self, sig, fr):
		pull.halt(
			"Received CTRL + C! Exiting Now!",
			True,
			"\r",
			pull.RED
		)

############################################
################# SLAB A ###################
############################################

class SLAB_A:

	def __init__(self, prs):
		self.verbose   = prs.verbose
		self.interface = prs.interface
		self.channels  = prs.channels
		self.essids    = prs.essids
		self.aps       = prs.aps
		self.stations  = prs.stations
		self.filters   = prs.filters
		self.output    = prs.output
		self.packets   = prs.packets
		self.code      = prs.code
		self.delay     = prs.delay

	def sniff(self):
		sniffer = SNIFFER(
			self.interface,
			self.channels,
			self.essids,
			self.aps,
			self.stations,
			self.filters,
			pull,
			self.verbose
		)

		sniffer.sniff()
		aps = sniffer._SNIFFER__ACCESSPOINTS
		return aps

	def pull_aps(self, aps):
		headers = [pull.BOLD + '#', 'BSSID', 'PWR', 'CH', 'ENC', 'CIPHER', 'AUTH', 'DEV', 'ESSID', 'STA\'S' + pull.END] if self.verbose else \
					[pull.BOLD + '#', 'BSSID', 'PWR', 'CH', 'ENC', 'CIPHER', 'AUTH', 'ESSID', 'STA\'S' + pull.END]
		rows = []
		for ap in list(aps.keys()):
			if self.verbose:
				rows.append([
						list(aps.keys()).index(ap),
						pull.DARKCYAN + aps[ ap ][ 'bssid' ].upper() + pull.END,
						pull.RED + str(aps[ ap ][ 'power' ]) + pull.END,
						aps[ ap ][ 'channel' ],
						pull.DARKCYAN + aps[ ap ][ 'encryption' ] + pull.END,
						pull.YELLOW + aps[ ap ][ 'cipher' ] + pull.END,
						pull.YELLOW +  aps[ ap ][ 'auth' ] + pull.END,
						aps[ ap ][ 'device' ],
						pull.GREEN + aps[ ap ][ 'essid' ] + pull.GREEN,
						pull.RED + str(len(aps[ ap ][ 'stations' ])) + pull.END
					])
			else:
				rows.append([
						list(aps.keys()).index(ap),
						pull.DARKCYAN + aps[ ap ][ 'bssid' ].upper() + pull.END,
						pull.RED + str(aps[ ap ][ 'power' ]) + pull.END,
						aps[ ap ][ 'channel' ],
						pull.DARKCYAN + aps[ ap ][ 'encryption' ] + pull.END,
						pull.YELLOW + aps[ ap ][ 'cipher' ] + pull.END,
						pull.YELLOW +  aps[ ap ][ 'auth' ] + pull.END,
						pull.GREEN + aps[ ap ][ 'essid' ] + pull.GREEN,
						pull.RED + str(len(aps[ ap ][ 'stations' ])) + pull.END
					])
		towrite = tabulate(rows, headers=headers) + "\n"
		pull.linebreak()
		pull.write(towrite)
		pull.linebreak()

	def extract(self, aps):
		alist = tuple(range(0, len(aps)))
		alist = [str(it) for it in alist]
		retval = int(pull.input( "?", "Enter Your Target Number: ", alist, pull.BLUE ))
		tgt   = aps.get( list(aps.keys())[ retval ] )
		return tgt

	def loop(self, tgt):
		bssid = tgt.get('bssid')
		essid = tgt.get('essid')
		channel = tgt.get('channel')
		power = tgt.get('power')
		device = tgt.get('device')
		encryption = tgt.get('encryption')
		cipher= tgt.get('cipher')
		auth  = tgt.get('auth')
		stations = tgt.get('stations')

		pull.print(
			"*",
			"TARGET BSS [{bss}] ESS [{ess}] CH [{ch}] PWR [{power}]".format(
				bss=pull.DARKCYAN + bssid.upper() + pull.END,
				ess=pull.YELLOW + essid + pull.END,
				ch =pull.RED + str(channel) + pull.END,
				power=pull.RED  + str(power)  + pull.END
			),
			pull.YELLOW
		)

		pull.print(
			"*",
			"TARGET SEC [{enc}] CPR [{cipher}] AUTH [{auth}] PWR [{stations}]".format(
				enc=pull.DARKCYAN + encryption + pull.END,
				cipher=pull.YELLOW + cipher + pull.END,
				auth =pull.RED + auth + pull.END,
				stations=pull.RED  + str(len(stations)) + pull.END
			),
			pull.YELLOW
		)

		pull.print(
			"-", "Stations Discovered ->", pull.DARKCYAN
		)

		for station in stations:
			pull.indent("-->", station.upper() + " (" + pull.DARKCYAN + pull.get_mac(station) + pull.END + ")", pull.YELLOW)

	def capture(self, tgt):
		bssid = tgt.get('bssid')
		essid = tgt.get('essid')
		channel = tgt.get('channel')
		power = tgt.get('power')
		device = tgt.get('device')
		encryption = tgt.get('encryption')
		cipher= tgt.get('cipher')
		auth  = tgt.get('auth')
		stations = tgt.get('stations')

		if len(stations) == 0:
			pull.halt("Found No Stations for This Target. Make a Rescan!", True, pull.RED)

		pull.print(
				"^",
				"Engaging with the target...",
				pull.GREEN
			)

		capture = CAPTURE(self.interface, bssid, essid, channel, power, device, encryption, cipher, auth, stations, self.output, self.packets, self.code, self.delay)
		capture.channeler()

		pull.print(
			"^",
			"Listening to Handshakes ...",
			pull.BLUE
		)

		capture.crater()
		capture.engage()

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

		aps = self.sniff()
		signal = SIGNALER()
		signal.changer()
		self.pull_aps( aps )
		tgt = self.extract(aps)
		self.loop( tgt )
		signal.origanl()
		del signal
		self.capture( tgt )


############################################
################# SLAB B ###################
############################################

class SLAB_B:

	def __init__(self, prs):
		self.verbose   = prs.verbose
		self.interface = prs.interface
		self.channels  = prs.channels
		self.essids    = prs.essids
		self.aps       = prs.aps
		self.stations  = prs.stations
		self.filters   = prs.filters
		self.output    = prs.output
		self.pauth     = prs.pauth
		self.passo     = prs.passo
		self.dauth     = prs.dauth
		self.dasso     = prs.dasso

	def sniff(self):
		sniffer = SNIFFER(
			self.interface,
			self.channels,
			self.essids,
			self.aps,
			self.stations,
			self.filters,
			pull,
			self.verbose
		)

		sniffer.sniff()
		aps = sniffer._SNIFFER__ACCESSPOINTS
		return aps

	def extract(self, aps):
		alist = tuple(range(0, len(aps)))
		alist = [str(it) for it in alist]
		retval = int(pull.input( "?", "Enter Your Target Number: ", alist, pull.BLUE ))
		tgt   = aps.get( list(aps.keys())[ retval ] )
		return tgt

	def pull_aps(self, aps):
		headers = [pull.BOLD + '#', 'BSSID', 'PWR', 'CH', 'ENC', 'CIPHER', 'AUTH', 'DEV', 'ESSID', 'STA\'S' + pull.END] if self.verbose else \
					[pull.BOLD + '#', 'BSSID', 'PWR', 'CH', 'ENC', 'CIPHER', 'AUTH', 'ESSID', 'STA\'S' + pull.END]
		rows = []
		for ap in list(aps.keys()):
			if self.verbose:
				rows.append([
						list(aps.keys()).index(ap),
						pull.DARKCYAN + aps[ ap ][ 'bssid' ].upper() + pull.END,
						pull.RED + str(aps[ ap ][ 'power' ]) + pull.END,
						aps[ ap ][ 'channel' ],
						pull.DARKCYAN + aps[ ap ][ 'encryption' ] + pull.END,
						pull.YELLOW + aps[ ap ][ 'cipher' ] + pull.END,
						pull.YELLOW +  aps[ ap ][ 'auth' ] + pull.END,
						aps[ ap ][ 'device' ],
						pull.GREEN + aps[ ap ][ 'essid' ] + pull.GREEN,
						pull.RED + str(len(aps[ ap ][ 'stations' ])) + pull.END
					])
			else:
				rows.append([
						list(aps.keys()).index(ap),
						pull.DARKCYAN + aps[ ap ][ 'bssid' ].upper() + pull.END,
						pull.RED + str(aps[ ap ][ 'power' ]) + pull.END,
						aps[ ap ][ 'channel' ],
						pull.DARKCYAN + aps[ ap ][ 'encryption' ] + pull.END,
						pull.YELLOW + aps[ ap ][ 'cipher' ] + pull.END,
						pull.YELLOW +  aps[ ap ][ 'auth' ] + pull.END,
						pull.GREEN + aps[ ap ][ 'essid' ] + pull.GREEN,
						pull.RED + str(len(aps[ ap ][ 'stations' ])) + pull.END
					])
		towrite = tabulate(rows, headers=headers) + "\n"
		pull.linebreak()
		pull.write(towrite)
		pull.linebreak()

	def loop(self, tgt):
		bssid = tgt.get('bssid')
		essid = tgt.get('essid')
		channel = tgt.get('channel')
		power = tgt.get('power')
		device = tgt.get('device')
		encryption = tgt.get('encryption')
		cipher= tgt.get('cipher')
		auth  = tgt.get('auth')
		stations = tgt.get('stations')

		pull.print(
			"*",
			"TARGET BSS [{bss}] ESS [{ess}] CH [{ch}] PWR [{power}]".format(
				bss=pull.DARKCYAN + bssid.upper() + pull.END,
				ess=pull.YELLOW + essid + pull.END,
				ch =pull.RED + str(channel) + pull.END,
				power=pull.RED  + str(power)  + pull.END
			),
			pull.YELLOW
		)

		pull.print(
			"*",
			"TARGET SEC [{enc}] CPR [{cipher}] AUTH [{auth}] PWR [{stations}]".format(
				enc=pull.DARKCYAN + encryption + pull.END,
				cipher=pull.YELLOW + cipher + pull.END,
				auth =pull.RED + auth + pull.END,
				stations=pull.RED  + str(len(stations)) + pull.END
			),
			pull.YELLOW
		)

	def fire(self, tgt):
		bssid = tgt.get('bssid')
		essid = tgt.get('essid')
		channel = tgt.get('channel')
		power = tgt.get('power')
		device = tgt.get('device')
		encryption = tgt.get('encryption')
		cipher= tgt.get('cipher')
		auth  = tgt.get('auth')
		beacon = tgt.get('beacon')
		stations = tgt.get('stations')

		pull.print(
				"^",
				"Engaging with the target...",
				pull.GREEN
			)

		pmkid = PMKID(
						self.interface, bssid, essid, channel, power, device, encryption, cipher, auth, beacon, stations,
						self.output, self.pauth, self.passo, self.dauth, self.dasso
					)

		pmkid.channeler()
		pmkid.engage()

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

		aps = self.sniff()
		self.pull_aps( aps )
		signal = SIGNALER()
		signal.changer()
		tgt = self.extract(aps)
		self.loop( tgt )
		self.fire( tgt )


#############################################
############## HANDLER ######################
#############################################


class HANDLER:

	def __init__(self, mode, prs):
		self.mode   = mode
		self.parser = prs

	def engage(self):
		if self.mode == 1:
			slab = SLAB_A(self.parser)
		elif self.mode == 2:
			slab = SLAB_B(self.parser)
			
		slab.engage()

class PARSER:

	def __init__(self, prs):
		# Mode Detector
		self.help      = self.helper(prs.help, prs.mode)
		self.mode      = self.mode(prs.mode)

		# Filters
		self.verbose   = prs.verbose

		if self.mode == 1:
			self.world     = prs.world
			self.interface = self.interface(prs.interface)
			self.channels  = self.channels(prs.channels)
			self.essids    = self.form_essids(prs.essids)
			self.aps       = self.form_macs(prs.aps)
			self.stations  = self.form_macs(prs.stations)
			self.filters   = self.form_macs(prs.filters)
			self.output    = self.output(prs.output)
			self.packets   = prs.packets if prs.packets >= 1 else pull.halt("Invalid Number of Packets Specified!", True, pull.RED)
			self.code      = prs.code    if prs.code    >= 1 else pull.halt("Invalid Code Given!", True, pull.RED)
			self.delay     = prs.delay   if prs.delay   >= 0 else pull.halt("Invalid Delay Specified!", True, pull.RED)

		elif self.mode == 2:
			self.world     = prs.world
			self.interface = self.interface(prs.interface)
			self.channels  = self.channels(prs.channels)
			self.essids    = self.form_essids(prs.essids)
			self.aps       = self.form_macs(prs.aps)
			self.stations  = self.form_macs(prs.stations)
			self.filters   = self.form_macs(prs.filters)
			self.output    = self.pmkid(prs.pmkid)
			self.pauth     = prs.pauth   if prs.pauth >= 1 else pull.halt("Invalid Number of Authentication Packets!", True, pull.RED)
			self.passo     = prs.passo   if prs.passo >= 1 else pull.halt("Invalud Number of Association Packets!", True, pull.RED)
			self.dauth     = prs.dauth   if prs.dauth >= 0 else pull.halt("Invalid Authentication Delay Specified!", True, pull.RED)
			self.dasso     = prs.dasso   if prs.dasso >= 0 else pull.halt("Invalid Assocaition Delay Specified!", True, pull.RED)

	def helper(self, hl, md):
		if hl:
			if not md:
				pull.help()
			else:
				if md == 1:
					pull.helpa()
				elif md == 2:
					pull.helpb()
				elif md == 3:
					pull.helpc()

	def mode(self, md):
		amodes = (1, 2, 3)
		if md in amodes:
			return md
		else:
			pull.halt("Invalid Mode Supplied. ", True, pull.RED)

	def pmkid(self, fl):
		if fl:
			return fl
		else:
			pull.halt("Capture File Not Provided. No PMKID will be Stored!", False, pull.RED)

	def output(self, fl):
		if fl:
			return fl
		else:
			pull.halt("Capture File Not Provided. No Output will be Stored!", False, pull.RED)

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
	parser = argparse.ArgumentParser(add_help=False)

	parser.add_argument('-h', '--help'         , dest="help"     , default=False, action="store_true")
	parser.add_argument('-m', '--mode'         , dest="mode"     , default=0 , type=int)
	parser.add_argument(      '--verbose'      , dest="verbose"  , default=False, action="store_true")

	# Mode 1, 2
	parser.add_argument('-i', '--interface'    , dest="interface", default="", type=str)
	parser.add_argument('-c', '--channel'      , dest="channels" , default=0 , type=int)
	parser.add_argument('-e', '--essids'       , dest="essids"   , default="", type=str)
	parser.add_argument('-a', '--accesspoints' , dest="aps"      , default="", type=str)
	parser.add_argument('-s', '--stations'     , dest="stations" , default="", type=str)
	parser.add_argument('-f', '--filters'      , dest="filters"  , default="", type=str)
	parser.add_argument(      '--world'        , dest="world"    , default=False, action="store_true")

	# Mode 1
	parser.add_argument('-o', '--output'       , dest="output"   , default="", type=str)
	parser.add_argument('-p', '--packets'      , dest="packets"  , default=10, type=int)
	parser.add_argument(      '--code'         , dest="code"     , default=7 , type=int)
	parser.add_argument(      '--delay'        , dest="delay"    , default=0.01, type=float)

	# Mode 2
	parser.add_argument('--pmkid'              , dest="pmkid"    , default="", type=str)
	parser.add_argument('--pkts-auth'          , dest="pauth"    , default=1 , type=int)
	parser.add_argument('--pkts-asso'          , dest="passo"    , default=1 , type=int)
	parser.add_argument('--delay-auth'         , dest="dauth"    , default=3 , type=float)
	parser.add_argument('--delay-asso'         , dest="dasso"    , default=5 , type=float)

	# Mode 3
	parser.add_argument('--mask'         , dest="mask"     , default="", type=str)
	parser.add_argument('-w', '--wordlist'     , dest="wordlist" , default="", type=str)
	parser.add_argument('-d', '--defer'        , dest="defer"    , default=0 , type=int)
	parser.add_argument('-r', '--read'         , dest="read"     , default="", type=str)
	parser.add_argument('--store'        , dest="store"    , default="", type=str)

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
		"\r", pull.DARKCYAN
	)

if __name__ == "__main__":
	pull = PULL()
	main()