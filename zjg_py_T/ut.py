import urllib2
import random
import time
import json
import subprocess
import sys
import os
from util.ConfigWrapper import ConfigWrapper


class DiamondRingUT:
    def __init__(self):
	self.config = {
		"Scan":{ 
			"URL":"http://127.0.0.1:5000/api/diamondring/v1.0/Scan"
		},
		"Cancel":{ 
			"URL":"http://127.0.0.1:5000/api/diamondring/v1.0/Cancel"
		},
		"GetProgress":{ 
			"URL":"http://127.0.0.1:5000/api/diamondring/v1.0/GetProgress?%s"
		},
		"GetResult":{ 
			"URL":"http://127.0.0.1:5000/api/diamondring/v1.0/GetResult?%s"
		},
	}

    def scan(self, param):
	return self.callAPI(self.config["Scan"]["URL"], "Post", param)

    def cancel(self, param):
	return self.callAPI(self.config["Cancel"]["URL"], "Post", param)

    def getProgress(self, param):
	return self.callAPI(self.config["GetProgress"]["URL"], "Get", param)

    def getResult(self, param):
	return self.callAPI(self.config["GetResult"]["URL"], "Get", param)
	

    def callAPI(self, url, method, param):
	if method == "Get":
		req = urllib2.Request(url % param)
	else:
		req = urllib2.Request(url, param)
		req.add_header("Content-Type", "application/json")
	resp = urllib2.urlopen(req)
	return resp.read()
	#params = urllib.urlencode({param})
	#if method == "Get":
	#	f = urllib.urlopen(url % params)
	#else:
	#	f = urllib.urlopen(url, params)
	#return f.read()

    def hanldeExtraSet(self, param):
	InputSet = set(param)
	AllSet = set(['DefaultPwd', 'WeakPwd', 'Shellshock'])
	IncludeSet = set()
	ExcludeSet = set()
	FinalSet = set()

	for t in InputSet:
		if t == 'All':
			IncludeSet |= AllSet
			continue
		if t[0] != '-':
			IncludeSet.add(t)
		else:
			ExcludeSet.add(t[1:])
	FinalSet = IncludeSet - ExcludeSet
	return FinalSet

    def initConfig(self, param=None):
	wrapper = ConfigWrapper(param)
	for t in wrapper.config.sections():
		print "[", t, "]"
		for k in wrapper.config.items(t):
			print k[0], ":", k[1]
		print ""
			

def LaunchScan():
	print "LaunchScan() test"
	print "=============================================================="
	dr = DiamondRingUT()
	Params = [
		#["Correct Input", "{\"TargetIP\":\"192.168.1.1,192.168.1.102,192.168.1.103\",\"ScanProfile\":{\"Type\":\"Fast\",\"SourceiFace\":\"eth0\",\"Extra\":[\"DefaultPwd\"]}}"],
		["Missing Host",  "{\"ScanProfile\":{\"Type\":\"Fast\",\"SourceiFace\":\"eth0\",\"Extra\":[\"DefaultPwd\"]}}"],
		["Missing Profile","{\"TargetIP\":\"192.168.37.1\"}"],
		]
	for t in Params:
		print t[0]
		result = dr.scan(t[1])
		print "Launch result:", result
		print ""
		time.sleep(5)


def FullScan():
	print "FullScan() test"
	print "=============================================================="
	dr = DiamondRingUT()
	param = "{\"TargetIP\":\"192.168.1.1,192.168.1.102,192.168.1.103\",\"ExcludeHosts\":[\"192.168.1.101\",\"192.168.1.12\"],\"ScanProfile\":{\"Type\":\"Fast\",\"SourceiFace\":\"eth0\",\"Extra\":[\"All\", \"DefaultPwd\", \"-WeakPwd\", \"-Shellshock\"],\"ExcludeDevTypeForVul\":[0, 4, 5]}}"
	result = dr.scan(param)
	print "Launch result:", result
	result_json = json.loads(result)
	sid = result_json["Response"]["SessionId"]
	while(len(sid)>0):
		time.sleep(10)
		param = "SessionId=%s" % (sid)
		result = dr.getProgress(param)
		print "Get progress:", result
		result_json = json.loads(result)
		if result_json.has_key("Response"):
			progress = result_json["Response"]["Progress"]
			if progress == "100":
				break
	time.sleep(2)
	param = "SessionId=%s&Lang=JA-JP" % (sid)
	result = dr.getResult(param)	
	print "Get result:", result

def CancelScan():
	print "CancelScan() test"
	print "=============================================================="
	dr = DiamondRingUT()
	param = "{\"TargetIP\":\"192.168.1.1\",\"ScanProfile\":{\"Type\":\"Fast\",\"SourceiFace\":\"eth0\",\"Extra\":[\"All\", \"DefaultPwd\", \"-WeakPwd\", \"-Shellshock\"]}}"
	result = dr.scan(param)
	print "Launch result:", result
	result_json = json.loads(result)
	sid = result_json["Response"]["SessionId"]
	while(sid != None):
		time.sleep(5)
		param = "SessionId=%s" % (sid)
		result = dr.getProgress(param)
		print "Get progress:", result
		result_json = json.loads(result)
		progress = result_json["Response"]["Progress"]
		print "Get progress:", progress
		if int(progress) >= 10:
			param = "{\"SessionId\":\"%s\"}" % (sid)
			result = dr.cancel(param)
			print "Cancel result:", result
			break
	time.sleep(2)
	param = "SessionId=%s&Lang=JA-JP" % (sid)
	url = dr.config["GetResult"]["URL"]
	result = dr.getResult(param)	
	print "Get result:", result

def GetProgress(sid):
	print "GetResult() test"
	print "=============================================================="
	dr = DiamondRingUT()
	param = "SessionId=%s" % sid
	result = dr.getProgress(param)
	print result

def HanldeExtraSet():
	print "HanldeExtraSet() test"
	print "=============================================================="
	Params = [
		['All'],
		['All', '-DefaultPwd'],
		['DefaultPwd', 'WeakPwd', 'Shellshock'],
		['DefaultPwd', 'WeakPwd', 'Shellshock', '-DefaultPwd', '-WeakPwd'],
		['Shellshock', '-DefaultPwd', '-WeakPwd'],
		]
	dr = DiamondRingUT()
	for t in Params:
		print "Input:", t
		result = dr.hanldeExtraSet(t)
		print "Output:", result

def CancelSpecificScan(sid):
	print "CancelSpecificScan() test"
	print "=============================================================="
	dr = DiamondRingUT()
	param = "{\"SessionId\":\"%s\"}" % (sid)
	result = dr.cancel(param)
	print "CancelSpecificScan:", result

def GetResult(sid):
	print "GetResult() test"
	print "=============================================================="
	dr = DiamondRingUT()
	param = "SessionId=%s&Lang=JA-JP" % (sid)
	result = dr.getResult(param)	
	print "GetResult:", result

def InitConfig(filename=None):
	print "InitConfig() test"
	print "=============================================================="	
	dr = DiamondRingUT()
	dr.initConfig(filename)


if __name__ == '__main__':
	LaunchScan()
	#GetResult('6d008006-d465-11e4-8cde-000c29f3f105')
	#GetProgress("234fbeb0-d94f-11e4-820c-000c29f3f105")
	#strFun = "GetProgress"
	#print callable(strFun), type(GetProgress)
	time.sleep(5)
	FullScan()
	time.sleep(5)
	CancelScan()
	#HanldeExtraSet()
	#InitConfig()
	
	

