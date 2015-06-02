import logging
import subprocess
import json
import uuid
import random
import time
import sys
import os

sys.path.append("./")
from util.MysqlWrapper import MysqlWrapper
from api.impl.openvas import OpenVASHandler, GetOpenVASHandlerInstance
from api.impl.parser import InteliParser
from util.ConfigWrapper import ConfigWrapper
from util.DRError import DRError

class Scanner: 
    _db_wrapper = None
    def __init__(self):
	self.config = {
	    "Namp": {
		"LogPath": "....",
		"FastScan": "...."
		},
	    "OpenVAS": {
		"LogPath": "....",
		"FastScan": "...."
		}
	}
	cfg_wrp = ConfigWrapper()
	db_name = cfg_wrp.config.get('Database', 'drdb_name')
	db_host = cfg_wrp.config.get('Database', 'host')
	db_user = cfg_wrp.config.get('Database', 'user')
	db_passwd = cfg_wrp.config.get('Database', 'passwd')
	self._db_wrapper = MysqlWrapper(db_host, db_name, db_user, db_passwd)
	self.err = DRError()


    def SetProgress(self, sid, progress):
	if len(sid) > 0 and progress != 0: 
		try:
			sql = "Update ScanSession Set Progress=%s Where SessionId = %s" 
			param = (str(progress), sid)
			self._db_wrapper.execute(sql, param)
		except Exception as e:
			print "sid:", sid, " Exception:", e
			return
	return

    def SetErrCode(self, sid, err_code):
	if len(sid) > 0 and len(err_code) >= 0: 
		try:
			sql = "Update ScanSession Set ErrCode=%s Where SessionId = %s" 
			param = (err_code, sid)
			self._db_wrapper.execute(sql, param)
		except Exception as e:
			print "sid:", sid, " Exception:", e
			return
	return

    def Scan(self, param):
	print "Scan() Param: " + param
	#1 prepare ENV
	st = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
	param_dict = json.loads(param)
	sid = param_dict["SessionId"]
	scan_log_dir = "/tmp/DRScanner/"
	if len(sid) > 0:
		scan_log_dir += sid
		if not os.path.isdir(scan_log_dir):
			os.makedirs(scan_log_dir)
		param_dict["LogDir"] = scan_log_dir
	else:
		print "Failed to get sid!!!"
		return

	scan_progress = 0
	parser = InteliParser()

	#2 Device identification scan
	#2.1 Start nmap scan
	dev_scan = param_dict
	nmap_dir = os.path.dirname(os.path.abspath(__file__))
	nmap_path = os.path.join(nmap_dir, "nmap.py")
	try:
		TargetIp = dev_scan["TargetIP"].replace(",", " ")
		dev_scan["TargetIP"] = TargetIp
		pDevScan = subprocess.Popen("python "+nmap_path, env={"Param":json.dumps(dev_scan)}, shell=True)
		sql = "INSERT NmapSession (SessionId, CreateTime, Pid, LogPath, CmdLine) VALUES (%s, %s, %s, %s, %s)" 
		param = (sid, st, pDevScan.pid, scan_log_dir, "Dev Id")
		self._db_wrapper.execute(sql, param)
		scan_progress += 10
		self.SetProgress(sid, scan_progress)
		pDevScan.wait()
		scan_progress += 20
		self.SetProgress(sid, scan_progress)
	except Exception as e:
		print "sid:", sid, " Exception:", e
		self.SetErrCode(sid, self.err.GetErrCode('DevScanFailed'))
		return

	#2.2 handle device scan log
	try:
		sql = "Select LogPath from NmapSession Where SessionId = %s and Pid = %s" 
		param = (sid, pDevScan.pid)
		dev_scan_log = self._db_wrapper.query(sql, param)
		if os.path.exists(dev_scan_log[0][0]):
			dev_result = parser.Parse(parser.Parser_Nmap, dev_scan_log[0][0])
			print "sid:", sid, " NMAP: scan result", dev_result
			#dev_result = [{'host_mac': '50:BD:5F:6A:6F:DE', 'device_model': 'TL-WR841N', 'host_ip': '192.168.1.1', 'device_category': 3, 'device_brand': 'TP-LINK', 'default_login_info': ['{"id":2,"version":"1.0","name":"TP-LINK TL-WR841N","category":"routers","SourceSessionID":["3","4"],"IP":"http://192.168.1.1","type":3,"target_check":{"http_response_code":[200],"http_body":{"include":["TL-WR841N"]}},"login_check":{"validation":{"http_response_code":[200],"http_body":{"exclude":["CheckPswLength"]}},"path":"/","credential":[{"username":"admin","password":"admin","username_key":"username","password_key":"password","ext":"value1"},{"username":"admin","password":"mac8.6","username_key":"username","password_key":"password","ext":"value1"}]}}']}]
			dev_id = dict()
			dev_id["device_info"] = dev_result
			st = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
			sql = "Update NmapSession Set EndTime=%s, Result=%s Where SessionId = %s and Pid = %s" 
			param = (st, json.dumps(dev_id), param_dict['SessionId'], pDevScan.pid)
			self._db_wrapper.execute(sql, param)
			scan_progress += 5
			self.SetProgress(sid, scan_progress)
		else:
			st = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
			sql = "Update NmapSession Set EndTime=%s, Result=%s Where SessionId = %s and Pid = %s" 
			param = (st, "", sid, pDevScan.pid)
			self._db_wrapper.execute(sql, param)
	except Exception as e:
		print "sid:", sid, " Exception:", e
		#LogUtil.getlogger().info(e)
		self.SetErrCode(sid, self.err.GetErrCode('DevLogParseFailed'))
		return

	#2.3 Filter host for next scan
	flt_hosts = list()
	port_range_tcp = set()
	port_range_udp = set()
	for t in dev_result:
		if param_dict["ScanProfile"].has_key("ExcludeDevTypeForVul") and t["device_category"] in param_dict["ScanProfile"]["ExcludeDevTypeForVul"]:
			continue
		else:
			flt_hosts.append(t["host_ip"])
			for p in t["tcp_ports_open"]: 	port_range_tcp.add(p)
			for p in t["tcp_ports_filter"]: port_range_tcp.add(p)
			for p in t["udp_ports_open"]: 	port_range_udp.add(p)
			for p in t["udp_ports_filter"]: port_range_udp.add(p)
			
	if len(flt_hosts) == 0:
		#No more device to scan
		self.SetProgress(sid, 100)
		return
	
	#3 Vulnerability type-I scan 
	if param_dict["ScanProfile"].has_key("Type") and param_dict["ScanProfile"]["Type"] != "Fastest":
		#3.1 start openvas scanner
		try:
			openvas = GetOpenVASHandlerInstance()
			hosts = ""
			port_range = ""
			vul_scan_log = ""
			#Filter Target by OS detection result, no windows and mac to avoid alarm from AV
			if len(flt_hosts) > 1:
				for t in flt_hosts:
					hosts += "%s," % (t) 
			else:
				hosts = flt_hosts[0]
			param_dict["TargetIP"] = hosts	

			## (TBD)Scan live port only for performanfce tune up
			#for t in port_range_tcp:
			#	port_range += "T:%s," % (t)
			#for t in port_range_udp:
			#	port_range += "U:%s," % (t)
			#if len(port_range) > 0:
			#	param_dict["PortRange"] = port_range
			#print "hosts:", hosts, " port_range:", port_range
			openvas_result = openvas.Scan(param_dict)
			print "sid:", sid, " openvas_result:", openvas_result
			openvas_result["SessionId"] = sid
			if openvas_result["status"] == "success":
				sql = "INSERT INTO OpenVASSession (SessionId, CreateTime,  TaskId, ReportId, LogPath, CmdLine) VALUES (%s, %s, %s, %s, %s, %s)"
				param = (sid, st, openvas_result['task_id'], openvas_result['report_id'], scan_log_dir, "Vul")
				self._db_wrapper.execute(sql, param)
				scan_progress += 10
				self.SetProgress(sid, scan_progress)
				while (True):
					time.sleep(5)
					result = openvas.GetProgress(openvas_result)
					print "sid: %s, OpenVAS progress: %s" % (sid, result["percentage"])
					if (result["percentage"] == "100" or result["percentage"] == "-1"):
						scan_progress += 20
						self.SetProgress(sid, scan_progress)
						break					
			else:
				self.SetErrCode(sid, self.err.GetErrCode('VulScanFailed'))
				return
		except Exception as e:
			print "sid:", sid, " Exception:", e
			self.SetErrCode(sid, self.err.GetErrCode('VulScanFailed'))
			return

		#3.2 dump scan log into file
		try:
			result = openvas.GetResult(openvas_result)
			if (result.has_key("status") and result["status"] == "success"):
				vul_scan_log = scan_log_dir + "/vul_scan_type_I.json"
				with open(vul_scan_log, 'w') as f:
					f.write(json.dumps(result))
		except Exception as e:
			print "sid:", sid, " Exception:", e
			#LogUtil.getlogger().info(e)
			self.SetErrCode(sid, self.err.GetErrCode('VulLogSaveFailed'))
			return		

		#3.3 handle vul scan log
		try:
			if os.path.exists(dev_scan_log[0][0]):
				result = parser.Parse(parser.Parser_Openvas, vul_scan_log)
				print "sid:", sid, " OpenVAS scan result:", result
				st = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
				sql = "Update OpenVASSession Set EndTime=%s, Result=%s Where SessionId = %s" 
				param = (st, json.dumps(result), sid)
				self._db_wrapper.execute(sql, param)
			else:
				sql = "Update OpenVASSession Set EndTime=%s, Result=%s Where SessionId = %s" 
				param = (st, "", sid)
				self._db_wrapper.execute(sql, param)
			scan_progress += 5
			self.SetProgress(sid, scan_progress)
		except Exception as e:
			print "sid:", sid, " Exception:", e
			#LogUtil.getlogger().info(e)
			self.SetErrCode(sid, self.err.GetErrCode('VulLogParseFailed'))
			return	
	else:
		scan_progress = 70
		self.SetProgress(sid, scan_progress)

	#4 start second round vulnerability scan if need
	if param_dict.has_key("ScanProfile") and param_dict["ScanProfile"].has_key("Extra"):
		param = json.dumps(param_dict)
		param_json = json.loads(param)
		ExtraSet = self.HanldeExtraSet(param_json["ScanProfile"]["Extra"])
		for t in ExtraSet:
			if t == "DefaultPwd" or t == "WeakPwd":
				def_login_sets = list()
				hosts = ""
				for s in dev_result:
					if s["host_ip"] in flt_hosts:
						def_login_sets.extend(s["default_login_info"])
						hosts += "%s " % s["host_ip"]
				#4.1 launch extra scan
				try:
					extra_scan_json = param_json
					extra_scan_json["ScanProfile"]["Type"] = t
					extra_scan_json["default_login_info"] = def_login_sets
					extra_scan_json["TargetIP"] = hosts
					nmap_dir = os.path.dirname(os.path.abspath(__file__))
					nmap_path = os.path.join(nmap_dir, "nmap.py")
					pExtraScan = subprocess.Popen("python "+nmap_path, env={"Param":json.dumps(extra_scan_json)}, shell=True)
					sql = "INSERT NmapSession (SessionId, CreateTime, Pid, LogPath, CmdLine) VALUES (%s, %s, %s, %s, %s)" 
					param = (sid, st, pExtraScan.pid, scan_log_dir, "Extra")
					self._db_wrapper.execute(sql, param)
					pExtraScan.wait()
				except Exception as e:
					print "sid:", sid, " Exception:", e
					#LogUtil.getlogger().info(e)
					self.SetErrCode(sid, self.err.GetErrCode('PwdScanFailed'))
					return	

				#4.2 send scan log to parser again
				sql = "Select LogPath from NmapSession Where SessionId = %s and Pid = %s" 
				param = (param_dict['SessionId'], pExtraScan.pid)
				extra_scan_log = self._db_wrapper.query(sql, param)
				#4.3 handle device scan log
				try:
					if os.path.exists(extra_scan_log[0][0]):
						pwd_result = parser.Parse(parser.Parser_Vul_DefPwd, extra_scan_log[0][0])
						#def_pwd_result = [{'check_status': 'true', 'password': 'admin', 'username': 'admin', 'host_ip': '192.168.1.1', 'host_mac': '50:BD:5F:6A:6F:DE'}]
						login_chk = dict()
						if t == "DefaultPwd":
							login_chk["default_login_check"] = pwd_result
						else:
							login_chk["weak_password_check"] = pwd_result
						sql = "Update NmapSession Set Result=%s Where SessionId = %s and Pid = %s" 
						param = (json.dumps(login_chk), sid, pExtraScan.pid)
						self._db_wrapper.execute(sql, param)
					else:
						sql = "Update NmapSession Set Result=%s Where SessionId = %s and Pid = %s" 
						param = ("", sid, pExtraScan.pid)
						self._db_wrapper._db_wrappersql.execute(sql, param)
				except Exception as e:
					print "sid:", sid, " Exception:", e
					#LogUtil.getlogger().info(e)
					self.SetErrCode(sid, self.err.GetErrCode('PwdParseFailed'))
					return
			scan_progress += 10
			self.SetProgress(sid, scan_progress)
	#8 do cleanup
	self.SetProgress(sid, 100)
	return 

    def Cancel(self, param_dict):
	pass 

    def HanldeExtraSet(self, param_dict):
	InputSet = set(param_dict)
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

if __name__ == '__main__':
	scanner = Scanner()
	scanner.Scan(os.getenv("Param"))
