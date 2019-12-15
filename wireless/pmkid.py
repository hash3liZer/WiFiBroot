import os
import re
import sys
import time
import curses
import random
import binascii
import threading
import subprocess
from pull import PULL
from scapy.sendrecv import sniff
from scapy.sendrecv import sendp
from scapy.utils    import PcapWriter
from scapy.packet   import Raw
from scapy.arch     import get_if_raw_hwaddr as HWADDR
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11Deauth
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import Dot11EltRSN
from scapy.layers.dot11 import Dot11FCS
from scapy.layers.dot11 import Dot11EltMicrosoftWPA
from scapy.layers.dot11 import Dot11EltCountry
from scapy.layers.dot11 import Dot11Auth
from scapy.layers.dot11 import Dot11AssoReq
from scapy.layers.dot11 import Dot11AssoResp
from scapy.layers.dot11 import Dot11EltRates
from scapy.layers.dot11 import RadioTapExtendedPresenceMask
from scapy.layers.dot11 import Dot11EltCountryConstraintTriplet
from scapy.layers.dot11 import RSNCipherSuite
from scapy.layers.dot11 import AKMSuite
from scapy.layers.dot11 import Dot11EltVendorSpecific
from scapy.layers.eap   import EAPOL

pull = PULL()

class PMKID:

	def __init__(self, iface, bss, ess, ch, pwr, dev, enc, cip, aut, beac, sts, wr, pauth, passo, dauth, dasso):
		self.interface    = iface
		self.bssid        = bss
		self.essid        = ess
		self.channel      = ch
		self.power        = pwr
		self.device       = dev
		self.encryption   = enc
		self.cipher       = cip
		self.auth         = aut
		self.beacon       = beac
		self.stations     = sts
		self.write        = wr
		self.pauth        = pauth
		self.passo        = passo
		self.dauth        = dauth
		self.dasso        = dasso

	def channeler(self):
		ch = str(self.channel)
		subprocess.call(['iwconfig', self.interface, 'channel', ch])

	def engage(self):
		return