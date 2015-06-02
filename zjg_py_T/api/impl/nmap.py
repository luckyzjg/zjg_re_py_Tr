import subprocess
import logging
import json
import os, sys
sys.path.append("./")
from util.MysqlWrapper import MysqlWrapper
from util.logutil import LogUtil
from util.ConfigWrapper import ConfigWrapper

class NMapHandler:
    _db_wrapper = None
    def __init__(self):
        self.config = {
                       'scan_type_hd': '-sn --no-stylesheet',
                       'scan_type_fastest': '-p T:80,139,445,443,23,135,8080,53,49152,5357,21,9100,22,515,631,49153,554,49154,49155,5000,U:1900,137,5353,53,67,138,68,161,3702,123,500,69,427,1026,4500,1023,1022,1029,111,1812 -T4 -sU -O -sT --script housecall --no-stylesheet',
                       'scan_type_fast': '-T4 -sU -O -sT -F --script housecall --no-stylesheet',
                       'scan_type_full': '-T4 -A --no-stylesheet',
                       'scan_type_defaultpwd': '-Pn -n -T4 -p T:80,88,443,631,7080,8080,8088,5800,3872,8180,8000 --script tm-http-auth --no-stylesheet',
                       'scan_type_weakpwd': '-Pn -n -T4 -p T:80,88,443,631,7080,8080,8088,5800,3872,8180,8000 --script tm-http-auth --no-stylesheet'
                       }
	cfg_wrp = ConfigWrapper()
	db_name = cfg_wrp.config.get('Database', 'drdb_name')
	db_host = cfg_wrp.config.get('Database', 'host')
	db_user = cfg_wrp.config.get('Database', 'user')
	db_passwd = cfg_wrp.config.get('Database', 'passwd')
	self._db_wrapper = MysqlWrapper(db_host, db_name, db_user, db_passwd)
        try:
            self.logger = logging
            #self.logger = LogUtil.getlogger()
        except:
            self.logger = logging
        
    def Scan(self):
        #1. Get Scan Param from Process Environment Variables
        #2. Start nmap process
        #3. Wait until nmap exists. 
        
        scan_param = os.getenv('Param', None)
        
        if scan_param is None:
            self.logger.error('Invalid scan param environment.')
            return
        
        self.logger.info('Scan Param is [%s]' % scan_param)
        
        scan_param = json.loads(scan_param)
        
        target_ip = scan_param['TargetIP']
        scan_type = scan_param['ScanProfile']['Type'].lower()
        source_iface = scan_param['ScanProfile']['SourceiFace']
        exclude_host = None
        
        if 'ExcludeHosts' in scan_param.keys():
            exclude_host = ','.join(scan_param['ExcludeHosts'])
        
        script_args = ''
        if 'defaultpwd' == scan_type or 'weakpwd' == scan_type:
            #Create default password pattern file.
    	    default_login_info_list = list()
    	    for t in scan_param['default_login_info']:
    		    default_login_info_list.append(json.loads(t.strip('"')))
                	
            pattern_filename = os.path.join(scan_param['LogDir'], 'defaultpwd_pattern.json')
            fp = open(pattern_filename, 'w')
            fp.write(json.dumps(default_login_info_list))
            fp.close()

            script_args += 'patternfile=%s' % pattern_filename
            
            if 'weakpwd' == scan_type:
                script_args += ',mode=weak_pwd'

        log_file  = os.path.join(scan_param['LogDir'], 'nmap_%s.xml' % scan_type)     
        cmd_line = 'nmap '
        
        cmd_line += ' ' + self.config['scan_type_%s' % scan_type]
        cmd_line += ' -e ' + source_iface
        
        if exclude_host:
            cmd_line += ' --exclude ' + exclude_host
        
        if script_args != '':
            cmd_line += ' --script-args %s' % script_args
        
        cmd_line += ' -oX ' + log_file    
        cmd_line += ' ' + target_ip
        
        self.logger.info('command line is [%s]', cmd_line) 
        sql = "Update NmapSession Set LogPath=%s, CmdLine=%s Where SessionId = %s and Pid = %s" 
        param = (log_file, cmd_line, scan_param['SessionId'], os.getppid())
        self._db_wrapper.execute(sql, param)   
        p = subprocess.Popen(cmd_line, stdout=subprocess.PIPE, shell=True)
        p.wait()
 
    def Cancel(self):
        pass

    def GetProgress(self):
        pass

    def GetResult(self):
        pass


if __name__ == '__main__':
    scan_param = os.getenv('Param', None)
    
    if scan_param is None:
        #for testing
        scan_param = {
                      'TargetIP': '10.0.2.1/24',
                      'ScanType': 'hd',
                      'LogDir': '/home/ares/tmp'                      
                      }
        
        scan_param = {
                      'TargetIP': '10.0.2.1/24',
                      'ScanType': 'fast',
                      'LogDir': '/home/ares/tmp'                      
                      }
        
        scan_param = {
                      'TargetIP': '10.0.2.1/24',
                      'ScanType': 'full',
                      'LogDir': '/home/ares/tmp'                      
                      }
    os.environ.setdefault('Param', json.dumps(scan_param))
    
    handler = NMapHandler()
    handler.Scan()
