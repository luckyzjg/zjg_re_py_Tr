# -*- coding: utf-8 -*-

import logging
import datetime
import os

class LogUtil:

	DEBUG, INFO, WARNING, ERROR, CRITICAL = 10, 20, 30, 40, 50

	def __init__(self):
		pass

	@staticmethod
	def initialize(loglevel, logfolder, logname):
		datenow = datetime.datetime.now()

		logging.basicConfig(level=loglevel,
	        format='%(asctime)s:%(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
	        datefmt='%Y-%m-%d %H:%M:%S',
	        filename = os.path.join(logfolder, '{0}-{1:0>2}-{2:0>2}-{3}.log'.format(datenow.year, datenow.month, datenow.day, logname)),
	        filemode='a+')

	@staticmethod
	def getlogger():
		return logging.getLogger('DR')