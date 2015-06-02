import subprocess
import json
import uuid
import random
import time
import sys
import os
import psutil
from openvas import OpenVASHandler, GetOpenVASHandlerInstance

sys.path.append("../..")
from util.xmltodict import parse as XML2Dict
from util.MysqlWrapper import MysqlWrapper
from util.logutil import LogUtil
from util.ConfigWrapper import ConfigWrapper
from util.DRError import DRError


class ScanMgr:
	def __init__(self):
		self.config = {
		    "DefaultLanguage": "EN-US",
		    "drdb_name":"",
		    "host":"",
		    "user":"",
		    "passwd":""
		}

		cfg_wrp = ConfigWrapper()
		self.config["db_name"] = cfg_wrp.config.get('Database', 'drdb_name')
		self.config["db_host"] = cfg_wrp.config.get('Database', 'host')
		self.config["db_user"] = cfg_wrp.config.get('Database', 'user')
		self.config["db_passwd"] = cfg_wrp.config.get('Database', 'passwd')

		self.err = DRError()

	def Scan(self, wsapp, param_dict):
		LogUtil.getlogger().info('ScanMgr::Scan()')
		print param_dict
		sid = str(uuid.uuid1())
		st = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
		#1 Parameter check
		if param_dict.has_key("TargetIP") == False or param_dict.has_key("ScanProfile") == False:
			#LogUtil.getlogger().error('Invalid param')	
			return {"ReturnCode": self.err.GetErrCode('InvalidParm')}

		#2 Record Start Session
		try:
			db_wrapper = MysqlWrapper(self.config["db_host"], self.config["db_name"], self.config["db_user"], self.config["db_passwd"])
			sql = "INSERT INTO ScanSession (SessionId, CreateTime,  TargetIP, ScanProfile, Progress, ErrCode) VALUES (%s, %s, %s, %s, %s, %s)"
			param = (sid, st, param_dict['TargetIP'], json.dumps(param_dict['ScanProfile']), int(0), int(0))
			db_wrapper.execute(sql, param)
		except Exception as e:
			print "sid:", sid, " Exception:", e
			LogUtil.getlogger().error(e)
			return {"ReturnCode": self.err.GetErrCode('DatabaseError')}

		#3 Start Scan Task
		param_dict["SessionId"] = sid
		scanner_dir = os.path.dirname(os.path.abspath(__file__))
		scanner_path = os.path.join(scanner_dir, "scanner.py")
		try:
			p = subprocess.Popen("python "+scanner_path, env={"Param":json.dumps(param_dict)}, shell=True, close_fds=True)
			if p.returncode:
				wsapp.logger.debug('Lanuch scanner process failed! ' + p.returncode)
				sql = "Update ScanSession Set ErrCode=%s Where SessionId= %s"
				param = (int(-1), sid)
				db_wrapper.execute(sql, param)
				return {"ReturnCode": self.err.GetErrCode('ScriptError')}
			else:
				sql = "Update ScanSession Set Pid=%s Where SessionId = %s"
				param = (int(p.pid), sid)
				db_wrapper.execute(sql, param)
		except Exception as e:
			print "sid:", sid, " Exception:", e
			LogUtil.getlogger().error(e)
			return {"ReturnCode": self.err.GetErrCode('ScriptError')}
		return {"ReturnCode": self.err.GetErrCode('Success'),
				"Response": {
				  "SessionId": sid
				}}

	def Cancel(self, wsapp, param_dict):
		wsapp.logger.debug('ScanMgr::Cancel()')
		print param_dict
		#1 Parameter check
		if param_dict.has_key("SessionId") == False:
			LogUtil.getlogger().error('Invalid param')	
			return {"ReturnCode": self.err.GetErrCode('InvalidParm')}
		sid = param_dict['SessionId']

		#2 End scan process
		#2.1 Nmap
		try:
			db_wrapper = MysqlWrapper(self.config["db_host"], self.config["db_name"], self.config["db_user"], self.config["db_passwd"])
			sql = "Select Pid from ScanSession Where SessionId = %s" 
			param = (sid)
			result = db_wrapper.query(sql, param)
			if len(result) > 0:
				process = psutil.Process(int(result[0][0]))
			    	for proc in process.get_children(recursive=True):
					print "sid:", sid, " Proc: ", proc
					proc.kill()
			    	process.kill()
			else:
				return {"ReturnCode": self.err.GetErrCode('InvalidSessionId')}
		except Exception as e:
			print "sid:", sid, " Exception:", e
		#2.2 OpenVAS
		try: 
			sql = "Select * from OpenVASSession Where SessionId = %s" 
			param = (sid)
			result = db_wrapper.query(sql, param)
			if len(result[0][8])>0:
				openvas = GetOpenVASHandlerInstance()
				param = dict()
				param["task_id"] = str(result[0][8])
				openvasresult = openvas.Cancel(param)
		except Exception as e:
			print "sid:", sid, " Exception:", e
		#2.3 Update ScanSession 
		try:
			st = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
			sql = "Update ScanSession Set EndTime=%s, Progress=%s, ErrCode=%s Where SessionId = %s" 
			param = (st, '100', self.err.GetErrCode('UserCancel'), sid)
			db_wrapper.execute(sql, param)
		except Exception as e:
			print "sid:", sid, " Exception:", e
			return {"ReturnCode": self.err.GetErrCode('ScriptError')}
		return {"ReturnCode": self.err.GetErrCode('Success')}

	def GetProgress(self, wsapp, param_dict):
		wsapp.logger.debug('DRScanMgr::GetProgress()')
		print param_dict
		#1 Parameter check
		if param_dict.has_key("SessionId") == False:
			LogUtil.getlogger().error('Invalid param')	
			return {"ReturnCode": self.err.GetErrCode('InvalidParm')}
		sid = param_dict['SessionId']

		#2 Query Get Progress By Session Id
		try:
			db_wrapper = MysqlWrapper(self.config["db_host"], self.config["db_name"], self.config["db_user"], self.config["db_passwd"])
			sql = "Select * from ScanSession Where SessionId = %s" 
			param = (sid)
			result = db_wrapper.query(sql, param)
			if result[0][6] == None:
				return {"ReturnCode": self.err.GetErrCode('InvalidSessionId')}

			devices_return = list()
			if int(result[0][6]) >= 35:
				sql = "Select Result from NmapSession Where SessionId = %s" 
				param = (sid)
				dev_result = db_wrapper.query(sql, param)
				for t in dev_result:
					if t[0] != None:
						tmp_json = json.loads(t[0])
						if tmp_json.has_key("device_info"):
							for s in tmp_json["device_info"]:
								device_return = dict()
								device_return["TargetIP"] = s["host_ip"]
								device_return["Mac"] = s["host_mac"]
								device_return["Model"] = s["device_model"]
								device_return["Category"] = s["device_category"]
								device_return["Brand"] = s["device_brand"]
								devices_return.append(device_return)
		
		except Exception as e:
			print "sid:", sid, " Exception:", e
			return {"ReturnCode": self.err.GetErrCode('DatabaseError')}
		return {"ReturnCode": str(result[0][7]),
				"Response": {
				  "Progress": str(result[0][6]),
				  "Devices": devices_return
				}}

	def GetResult(self, wsapp, param_dict):
		wsapp.logger.debug('ScanMgr::GetResult()')
		print param_dict
		#1 Parameter check
		if param_dict.has_key("SessionId") == False:	
			return {"ReturnCode": self.err.GetErrCode('InvalidParm')}
		sid = param_dict['SessionId']

		#2 Get ErrCode inform From ScanSession
		try: 
			db_wrapper = MysqlWrapper(self.config["db_host"], self.config["db_name"], self.config["db_user"], self.config["db_passwd"])
			sql = "Select ErrCode from ScanSession Where SessionId = %s" 
			param = (sid)
			err_result = db_wrapper.query(sql, param)
			if len(err_result)>0:
				if str(err_result[0][0])!=self.err.GetErrCode('Success'):
					return {"ReturnCode": str(err_result[0][0])}
			else:
				return {"ReturnCode": self.err.GetErrCode('InvalidSessionId')}				
		except Exception as e:
			print "sid:", sid, " Exception:", e
			return {"ReturnCode": self.err.GetErrCode('DatabaseError')}

		#3 Get device inform From NmapSession
		try: 
			sql = "Select Result from NmapSession Where SessionId = %s" 
			param = (sid)
			dev_result = db_wrapper.query(sql, param)
		except Exception as e:
			print "sid:", sid, " Exception:", e
			return {"ReturnCode": self.err.GetErrCode('DatabaseError')}
		#4 Get vulerability type-I inform from OpenVAS Session
		try: 
			sql = "Select Result from OpenVASSession Where SessionId = %s" 
			param = (sid)
			vul_result = db_wrapper.query(sql, param)
		except Exception as e:
			print "sid:", sid, " Exception:", e
			return {"ReturnCode": self.err.GetErrCode('DatabaseError')}

		#5 Merge Scan Result
		#5.1 Merge Device Scan Result
		devices_return = list()
		default_login_check = list()
		weak_password_check = list()
		for t in dev_result:
			tmp_json = json.loads(t[0])
			if tmp_json.has_key("device_info"):
				for s in tmp_json["device_info"]:
					device_return = dict()
					device_return["TargetIP"] = s["host_ip"]
					device_return["Mac"] = s["host_mac"]
					device_return["Model"] = s["device_model"]
					device_return["Category"] = s["device_category"]
					device_return["Brand"] = s["device_brand"]
					device_return["Default_Login_Info"] = list()
					device_return["Weak_Login_Info"] = list()
					devices_return.append(device_return)
			if tmp_json.has_key("default_login_check"):
				default_login_check.extend(tmp_json["default_login_check"])
			if tmp_json.has_key("weak_password_check"):
				weak_password_check.extend(tmp_json["weak_password_check"])	

		#5.2 Merge Scan Result
		for t in devices_return:
			#5.2.1 Default password result
			for s in default_login_check:
				if t["TargetIP"] == s["host_ip"]:
					item = dict()
					account = dict()
					account["username"] = s["username"]
					account["password"] = s["password"]
					item["IP"] = s["host_ip"]
					item["Path"] = s["path"]
					if s["check_status"] == "true":
						item["Hit"] = "1"
					else:
						item["Hit"] = "0"
					item["Login_Accounts"] = account
					t["Default_Login_Info"].append(item)
			#5.2.2 Weak password result
			for s in weak_password_check:
				if t["TargetIP"] == s["host_ip"]:
					item = dict()
					account = dict()
					account["username"] = s["username"]
					account["password"] = s["password"]
					item["IP"] = s["host_ip"]
					item["Path"] = s["path"]
					if s["check_status"] == "true":
						item["Hit"] = "1"
					else:
						item["Hit"] = "0"
					item["Login_Accounts"] = account
					t["Weak_Login_Info"].append(item)
			#5.2.3 Merge Shellshock Scan Result

		vul_report_return = list()
		if len(vul_result)> 0:
			vul_report = json.loads(vul_result[0][0])
			vul_report_json = json.loads(vul_report)
			if vul_report_json["report"]["report"]["results"].has_key("result"):
				vul_report_return = vul_report_json["report"]["report"]["results"]["result"] 

		return {"ReturnCode":err_result[0][0],
				"Response": {
				  "Devices": devices_return,
				  "VulReports": vul_report_return
				}}

scanMgr = ScanMgr()
def GetScanMgrInstance():
    return scanMgr
        
if __name__ == '__main__':
    LogUtil.getlogger().info("scanMgr")
