import ConfigParser
import os

class ConfigWrapper:
	configpath = None
	config = None
	def __init__(self, filename=None):
		_CurDir_Path = os.path.dirname(os.path.abspath(__file__))
		self.configpath = filename or os.path.join(_CurDir_Path, "../dr.conf")
		print self.configpath
		self.config = ConfigParser.ConfigParser()
		self.config.read(self.configpath)



	
