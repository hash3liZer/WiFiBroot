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
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11Deauth
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import Dot11EltRSN
from scapy.layers.dot11 import Dot11FCS
from scapy.layers.dot11 import Dot11EltMicrosoftWPA
from scapy.layers.dot11 import Dot11EltCountry
from scapy.layers.eap   import EAPOL

class CRACK:

	def __init__(self, packets, passes, defer, store):
		self.packets = packets
		self.passes  = passes
		self.defer   = defer
		self.store   = store

	def engage(self):
		return