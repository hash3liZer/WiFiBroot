
import sys
import os

__log__ = r'''%s
             _____  ___   ___               |
 ||      ||*|     *||  \ |   \   ___   _____|__
 ||      ||||_____|||___||___|| /   \ /   \ |
  \  /\  / ||     |||   ||   / ||   |||   |||   ||
   \/  \/  ||     |||__/ |   \  \___/ \___/ \\__/ 
%s 
          %sv1.0. Coded by @hash3liZer.%s
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
		print "%s[*]%s %s" % (self.YELLOW, self.END, statement)
		return

	def error(self, statement, *args, **kwargs):
		print "%s[!]%s %s" % (self.RED, self.END, statement)
		return

	def up(self, statement, *args, **kwargs):
		print "%s[^]%s %s" % (self.BLUE, self.END, statement)
		return

	def use(self, statement, *args, **kwargs):
		print "%s[$]%s %s" % (self.GREEN, self.END, statement)
		return

	def question(self, statement, *args, **kwargs):
		q = raw_input("%s[?]%s %s" % (self.PURPLE, self.END, statement))
		return q

	def delete(self, statement, *args, **kwargs):
		print "%s[#]%s %s" % (self.CYAN, self.END, statement)
		return

	def linebreak(self):
		print "\n"
		return

	def right(self, statement, *args, **kwargs):
		print "%s[>]%s %s" % (self.DARKCYAN, self.END, statement)

	def lineup(self, *args, **kwargs):
		sys.stdout.write(self.LINEUP)

	def logo(self):
		print __log__ % (self.RED+self.BOLD, self.END, self.BOLD, self.END)