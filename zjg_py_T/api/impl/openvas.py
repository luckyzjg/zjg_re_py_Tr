import logging
import subprocess, uuid

import sys
sys.path.append("../..")
from util.xmltodict import parse as XML2Dict
from util.logutil import LogUtil
from util.ConfigWrapper import ConfigWrapper

class OpenVASHandler:
    def __init__(self):
        self.config = {
            "Common": {
                "username":"admin123",
                "password":"3a176bc1-4ab7-4cf5-b275-8092c0afd8cc",
                "max_hosts": "10"
            },
            "DefaultTarget": {
                "Description": "localhost",
                "target": "b493b7a8-7489-11df-a3ec-002264764cea"
            },
            "QuickScan":{
                "Description": "Full and fast",
                "config": "daba56c8-73ec-11df-a475-002264764cea"
            },
            "DeepScan":{
                "Description": "Full and deep",
                "config": "708f25c4-7489-11df-8094-002264764cea"
            }
        }

	cfg_wrp = ConfigWrapper()
	self.config["Common"]["username"] = cfg_wrp.config.get('Openvas', 'username')
	self.config["Common"]["password"] = cfg_wrp.config.get('Openvas', 'password')
	self.config["Common"]["max_hosts"] = cfg_wrp.config.get('Openvas', 'max_hosts')
        
        self.opt = {
            "username": self.config["Common"]["username"],
            "password": self.config["Common"]["password"],
        }
        
    def Scan(self, param_json):
        sid = param_json['SessionId']
        print 'sid=' + sid + ' OpenVASHandler::Scan()'
        ip = param_json["TargetIP"]
	if param_json.has_key("PortRange"):
		port_range = param_json["PortRange"]
	else:
		port_range = ""
        target_id = self.config["DefaultTarget"]["target"]
        self.opt["name"] = "target_" + uuid.uuid1().get_hex()
        self.opt["ip"] = ip
        self.opt["port_range"] = port_range
        parameter = "omp --username %s --password %s --create-target --name %s --ip %s" % (self.opt["username"], self.opt["password"], self.opt["name"], self.opt["ip"])
        if self.opt["port_range"]:
            parameter += " --port-range " + self.opt["port_range"]
        if ip != "localhost" and ip != "127.0.0.1":
            p = subprocess.Popen(parameter, stdout=subprocess.PIPE, shell=True)
            p.wait()
            target_id = p.stdout.read().strip()
        print 'sid=' + sid + ' targetid = ' + target_id

        if target_id:
            self.opt["max_hosts"] = self.config["Common"]["max_hosts"]
            self.opt["source_iface"] = param_json["ScanProfile"]["SourceiFace"]
            self.opt["config"] = self.config["QuickScan"]["config"] if param_json["ScanProfile"]["Type"] == "Fast" else self.config["DeepScan"]["config"]
            self.opt["target_id"] = target_id
            parameter = "omp --username %s --password %s --create-task --config %s --name %s --target %s" % (self.opt["username"], self.opt["password"], self.opt["config"], self.opt["name"], self.opt["target_id"])
            if self.opt["max_hosts"]:
                parameter += " --max-hosts " + self.opt["max_hosts"]
            if self.opt["source_iface"]:
                parameter += " --source-iface " + self.opt["source_iface"]
            p = subprocess.Popen(parameter, stdout=subprocess.PIPE, shell=True)
            p.wait()
            task_id = p.stdout.read().strip()
            print 'sid=' + sid + ' taskid = ' + task_id

            if task_id:
                self.opt["task_id"] = task_id
                parameter = "omp --username %s --password %s --start-task %s" % (self.opt["username"], self.opt["password"], self.opt["task_id"])
                p = subprocess.Popen(parameter, stdout=subprocess.PIPE, shell=True)
                p.wait()
                report_id = p.stdout.read().strip()
                return {"status": "success", "task_id": task_id, "report_id": report_id}
        return {"status": "fail", "reason": "Unknown"}
        
    def Cancel(self, param_json):
        sid = param_json['SessionId']
        print 'sid=' + sid + ' OpenVASHandler::Cancel()'
        self.opt["task_id"] = param_json["task_id"]
        parameter = "omp --username %s --password %s --stop-task %s" % (self.opt["username"], self.opt["password"], self.opt["task_id"])
        p = subprocess.Popen(parameter, stdout=subprocess.PIPE, shell=True)
        p.wait()
        stop_task_result = p.stdout.read()
        print 'sid=' + sid + ' stop task result = ' + stop_task_result

        if '404' in stop_task_result:
            return {"status": "fail", "reason": "No such task"}
        
        """ don't need to delete task currently
        p = subprocess.Popen("omp --username " + self.opt["username"]
                           + " --password " + self.opt["password"]
                           + " --delete-task " + self.opt["task_id"], stdout=subprocess.PIPE, shell=True)
        p.wait()
        delete_task_result = p.stdout.read()
        wsapp.logger.debug('delete task result = ' + delete_task_result)
        """
        return {"status": "success"}

    def GetProgress(self, param_json):
        sid = param_json['SessionId']
        print 'sid=' + sid + ' OpenVASHandler::GetProgress()'
        self.opt["task_id"] = param_json["task_id"]
        self.opt["report_id"] = param_json["report_id"]
        parameter = "omp --username %s --password %s --get-tasks %s" % (self.opt["username"], self.opt["password"], self.opt["task_id"])
        p = subprocess.Popen(parameter, stdout=subprocess.PIPE, shell=True)
        p.wait()
        task_info = p.stdout.read()
        
        if task_info:
            print 'sid=' + sid + ' task_info = ' + task_info
            running_status = task_info.split()[1]
            print 'sid=' + sid + ' running_status = ' + running_status
            parameter = "omp --username %s --password %s --get-report %s" % (self.opt["username"], self.opt["password"], self.opt["report_id"])
            p = subprocess.Popen(parameter, stdout=subprocess.PIPE, shell=True)
            p.wait()
            get_report_result = p.stdout.read()
            json_result = XML2Dict(get_report_result)
            return {"running_status": running_status, "percentage": json_result["report"]["report"]["task"]["progress"]}
        
        return {"status": "fail", "reason": "Unknown"}

    def GetResult(self, param_json):
        sid = param_json['SessionId']
        print 'sid=' + sid + ' OpenVASHandler::GetResult()'
        parameter = "omp --username %s --password %s --get-report %s" % (self.opt["username"], self.opt["password"], self.opt["report_id"])
        self.opt["report_id"] = param_json["report_id"]
        p = subprocess.Popen(parameter, stdout=subprocess.PIPE, shell=True)
        p.wait()
        get_report_result = p.stdout.read()
        json_result = XML2Dict(get_report_result)
        json_result["status"] = "success"
        json_result["percentage"] = "%s" % json_result["report"]["report"]["task"]["progress"]
        return json_result

openvasHandler = OpenVASHandler()
def GetOpenVASHandlerInstance():
    return openvasHandler
        
if __name__ == '__main__':
    print "OpenVASHandler"
