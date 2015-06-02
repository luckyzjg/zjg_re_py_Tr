# -*- coding: utf-8 -*-

import re
from lxml import etree
import MySQLdb
import sys
import os
import json
import re
import codecs
import sys
sys.path.append("../..")
from util.MysqlWrapper import MysqlWrapper
from util.logutil import LogUtil
from util.ConfigWrapper import ConfigWrapper

class InteliParser:

	Parser_Nmap, Parser_Openvas, Parser_Vul_DefPwd = range(1, 4)
	(Device_Unknown, 
	Device_Cam, Device_Nas, Device_Router, Device_WindowsOS, 
	Device_MacOS, Device_IOS, Device_Printer, Device_GameConsole, 
	Device_MediaPlayer, Device_SmartTV, Device_DiscPlayer,
	Device_Other) = range(0, 13)

	_upnp_query = _http_hp_query = _wsdd_query = '''SELECT login_info_id from {0} WHERE {1} = %s {2}'''
	_upnp_like_query = _http_hp_like_query = _wsdd_like_query = '''SELECT login_info_id from {0} WHERE {1} like %s {2}'''
	_iot_login_query = '''SELECT login_info from {0} WHERE {1} = %s'''
	
	_Ptn_Type_Router_Upnp, _Ptn_Type_Router_Http, _Ptn_Type_IPCam_upnp = range(0, 3)

	_Router_Upnp_Ptn, _Router_Hpage_Ptn = "router_upnp.ptn", "router_httphp.ptn"
	_IPCam_Upnp_Ptn = "ipcam_upnp.ptn"

	_IP_KEY, _MAC_KEY, _MODEL_KEY, _CATEGORY_KEY, _BRAND_KEY, _DEFAULT_LOGIN_KEY = \
		"host_ip", "host_mac", "device_model", "device_category", "device_brand", "default_login_info"
	
	_TCP_PORTS_OPEN_KEY, _TCP_PORTS_FILTER_KEY, _UDP_PORTS_OPEN_KEY, _UDP_PORTS_FILTER_KEY = \
		"tcp_ports_open", "tcp_ports_filter", "udp_ports_open", "udp_ports_filter"

	_CHECK_STATUS_KEY, _USER_NAME_KEY, _PASS_WORD_KEY, _PATH_KEY = \
		"check_status", "username", "password", "path"

	_CurDir_Path = os.path.dirname(os.path.abspath(__file__))

	_db_wrapper = None

	def __init__(self):

		cfg_wrp = ConfigWrapper()
		db_name = cfg_wrp.config.get('Database', 'iotdb_name')
		db_host = cfg_wrp.config.get('Database', 'host')
		db_user = cfg_wrp.config.get('Database', 'user')
		db_passwd = cfg_wrp.config.get('Database', 'passwd')

		self._db_wrapper = MysqlWrapper(db_host, db_name, db_user, db_passwd)

	def Parse(self, parse_type, file_name):
		if parse_type == self.Parser_Nmap:
			
			LogUtil.getlogger().info('start to parse Nmap result')
			self._load_ptns()
			devices_info = list()
			devices_info = self._parse_host(file_name)
			
			print devices_info
			return devices_info

		elif parse_type == self.Parser_Vul_DefPwd:

			LogUtil.getlogger().info('start to parse Vulnerability[Default Password]')
			vuls_info = list()
			vuls_info = self.parse_vul_defpwd(file_name)

			print vuls_info
			return vuls_info
		else:
			with open(file_name) as f:
				return f.read()

	def GetHttpAuthPtn(self):

		ptn_file = os.path.join(self._CurDir_Path, 'http-auth-pattern.json')
		with open(ptn_file) as f:
			return f.read()

	_Type_KeyValue, _Type_KeyContent = range(1, 3)

	def _get_elem_data(self, node, type, path_name):
		if node is not None:
			nodes = node.xpath(path_name)
			if type == self._Type_KeyValue:
				return nodes[0].text if nodes and nodes[0].text else ""
			else:
				return ''.join(nodes[0].itertext()) if nodes else ""

		return ""

	def _validate_xml(self, filename):

		is_valid = True
		try:
			etree.parse(filename)
		except:
			is_valid = False

		return is_valid

	def _parse_host(self, filename):

		flog = open(filename)
		devices = list()

		if flog:

			if not self._validate_xml(filename):
				print 'filename[%s] is not a valid file' %(filename)
				flog.close()

				return devices

			contents = flog.read()
			xml_root = etree.fromstring(contents)

			hosts = xml_root.xpath(".//host")

			for host in hosts:
				print 'parse 1 host'
				ipaddr = ""
				ipaddr_nodes = host.xpath(".//address[@addrtype='ipv4']")
				if ipaddr_nodes:
					ipaddr = ipaddr_nodes[0].get("addr")

				macaddr, vendor = "", ""
				macaddr_nodes = host.xpath(".//address[@addrtype='mac']")
				if macaddr_nodes:
					macaddr = macaddr_nodes[0].get("addr")
					vendor = macaddr_nodes[0].get("vendor")

				print 'ip address[%s], mac address[%s], vendor[%s]' %(ipaddr, macaddr, vendor)

				tcp_ports_open = list()
				tcp_ports_filter = list()
				udp_ports_open = list()
				udp_ports_filter = list()

				ports = host.xpath(".//port")
				for port in ports:
					proto = port.get("protocol")
					portid = port.get("portid")

					for state in port.xpath(".//state"):
						status = state.get("state")

						if proto == "tcp":
							if status == "open":
								tcp_ports_open.append(portid)
							elif status == "open|filtered":
								tcp_ports_filter.append(portid)
						elif proto == "udp":
							if status == "open":
								udp_ports_open.append(portid)
							elif status == "open|filtered":
								udp_ports_filter.append(portid)

				ret, result = self._parse_upnp(host, self._db_wrapper)

				if ret:
					#print 'device information=', result #json.dumps(result)
					pass
				else:
					print 'no upnp data'
					ret, result = self._parse_http_hp(host, self._db_wrapper)
					if ret:
						pass
					else:
						print 'no http homepage data'
						ret, result = self._parse_wsdd_discover(host, self._db_wrapper)
						if ret:
							pass
						else:
							print 'no wsdd data'
							ret, result = self._parse_model_name(host, self._db_wrapper)
							if ret:
								pass
							else:
								print 'no model name data'
								ret, result = self._parse_os_type(host, self._db_wrapper)
								if ret:
									result[self._BRAND_KEY] = vendor
								else:
									result[self._CATEGORY_KEY] = self.Device_Other if vendor != "" else self.Device_Unknown
									result[self._BRAND_KEY] = vendor
									result[self._MODEL_KEY] = ""
									result[self._DEFAULT_LOGIN_KEY] = list()
							
				
				result[self._IP_KEY] = ipaddr
				result[self._MAC_KEY] = macaddr
				result[self._TCP_PORTS_OPEN_KEY] = tcp_ports_open
				result[self._TCP_PORTS_FILTER_KEY] = tcp_ports_filter
				result[self._UDP_PORTS_OPEN_KEY] = udp_ports_open
				result[self._UDP_PORTS_FILTER_KEY] = udp_ports_filter

				devices.append(result)

			flog.close()

			return devices
		else:
			print 'read file fail'
			return devices

	def _format_dev_login_result(self, dev_type, dev_brand, dev_model, dev_sql_results, sqlwrapper):
		result = dict()
		result[self._CATEGORY_KEY] = dev_type
		result[self._BRAND_KEY] = dev_brand
		result[self._MODEL_KEY] = dev_model
		loginfos = list()

		for item in dev_sql_results:
			sql = self._iot_login_query.format('TIOTLoginInfo', 'id')
			info_id = str(item)
			print info_id, type(item)
			ret, loginfo_result = self._query_result(sql, info_id, sqlwrapper)
			if ret:
				loginfos = [x[0] for x in loginfo_result]
		result[self._DEFAULT_LOGIN_KEY] = loginfos
		return result

	def _query_ptn_from_db(self, pattern_type, xml_node, brand_names, q_model_sql, q_like_model_sql, sqlwrapper):
		
		new_brand, models = self._parse_ptn(pattern_type, xml_node, brand_names)

		if len(models) > 0:
			for new_model in models:
				print 'new_model', new_model
				ret, sql_query_result = self._query_result(q_model_sql, new_model, sqlwrapper)
				if ret == False:
					print 'Try like search instead of exact search'
					ret, sql_query_result = self._query_result(q_like_model_sql, "%"+new_model+"%", sqlwrapper)
					if ret == True:
						return True, new_brand, new_model, sql_query_result
					else:
						continue
				else:
					return True, new_brand, new_model, sql_query_result
			return False, "", "", ()
		else:
			print '[_query_ptn_from_db] Can not parse model with pattern!'
			return False, "", "", ()

	def _get_device_info(self, q_model_sql, model_name, brand_name, sqlwrapper, brand_names, ptn_type, upnp_node, q_like_model_sql, device_type):

		ret, sql_query_result = self._query_result(q_model_sql, model_name, sqlwrapper)
		if ret == False:
			print 'can not query model from db, try pattern'
			if len(brand_names) > 0:

				ret, new_brand, new_model, sql_query_result = self._query_ptn_from_db(ptn_type, upnp_node, brand_names, 
					q_model_sql, q_like_model_sql, sqlwrapper)
				print 'new_brand, new_model', new_brand, new_model
				if ret == True:
					result = self._format_dev_login_result(device_type, new_brand, new_model, [x[0] for x in sql_query_result], sqlwrapper)
					return ret, result
				else:
					return False, {}
			else:
				return False, {}
		else:
			result = self._format_dev_login_result(device_type, brand_name, model_name, [x[0] for x in sql_query_result], sqlwrapper)
			return True, result

	def _testSqlStr(self):
		print self._upnp_query.format('TRouterLoginInfo','model', '')
		
				
	def _parse_upnp(self, host, sqlwrapper):
		

		print 'Parse UPNP Info'

		upnp_nodes = host.xpath(".//script[@id='upnp-info']")
		

		if upnp_nodes:
			brand_names = list()
			model_name = self._get_elem_data(upnp_nodes[0], self._Type_KeyValue, ".//elem[@key='modelName']")
			manufacturer = self._get_elem_data(upnp_nodes[0], self._Type_KeyValue, ".//elem[@key='manufacturer']")
			friend_name = self._get_elem_data(upnp_nodes[0], self._Type_KeyValue, ".//elem[@key='friendlyName']")
			model_desc = self._get_elem_data(upnp_nodes[0], self._Type_KeyValue, ".//elem[@key='modelDescription']")
			res_body = self._get_elem_data(upnp_nodes[0], self._Type_KeyValue, ".//elem[@key='response_body']")
			
			if manufacturer != "":
				brand_names.append(manufacturer)
			if friend_name != "":
				brand_names.append(friend_name)
			if model_desc != "":
				brand_names.append(model_desc)

			#Use manufacturer as default brand name
			brand_name = manufacturer   

			q_model_sql = ""
			q_brand_sql = ""
			q_like_model_sql = ""

			device_type = self.Device_Unknown
			
			if len(model_name) > 0:
				print 'modelName=', model_name

				# Router
				device_type = self.Device_Router	
				q_model_sql = self._upnp_query.format('TRouterLoginInfo','model', '')
				q_brand_sql = self._upnp_query.format('TRouterLoginInfo','brand', 'limit 0,5')
				q_like_model_sql = self._upnp_like_query.format('TRouterLoginInfo','model', 'limit 0,5')

				ret, result = self._get_device_info(q_model_sql, model_name, brand_name, sqlwrapper, brand_names, 
					self._Ptn_Type_Router_Upnp, upnp_nodes[0], q_like_model_sql, device_type)
				if ret:
					return True, result

				# IP Camera
				device_type = self.Device_Cam
				q_model_sql = self._upnp_query.format('TIPCameraLoginInfo','model', '')
				q_brand_sql = self._upnp_query.format('TIPCameraLoginInfo','brand', 'limit 0,5')
				q_like_model_sql = self._upnp_like_query.format('TIPCameraLoginInfo','model', 'limit 0,5')

				ret, result = self._get_device_info(q_model_sql, model_name, brand_name, sqlwrapper, brand_names, 
					self._Ptn_Type_IPCam_upnp, upnp_nodes[0], q_like_model_sql, device_type)
				if ret:
					return True, result

				# NAS
				device_type = self.Device_Nas	
				q_model_sql = self._upnp_query.format('TNASLoginInfo','model', '')
				q_brand_sql = self._upnp_query.format('TNASLoginInfo','brand', 'limit 0,5')
				q_like_model_sql = self._upnp_like_query.format('TNASLoginInfo','model', 'limit 0,5')

				ret, sql_query_result = self._query_result(q_model_sql, model_name, sqlwrapper)
				if ret:
					result = self._format_dev_login_result(device_type, brand_name, model_name, [x[0] for x in sql_query_result], sqlwrapper)
					return True, result
				else:
					
					return False, {}

				return False, {}
				
			else:
				print 'No model name'
				return False, {}
			
		else:
			return False, {}

	def _parse_http_hp(self, host, sqlwrapper):

		print 'Parse home page'

		httphp_nodes = host.xpath(".//script[@id='http-homepage']")

		if httphp_nodes:

			resp_header = self._get_elem_data(httphp_nodes[0], self._Type_KeyContent, ".//table[@key='response_header']")
			resp_body = self._get_elem_data(httphp_nodes[0], self._Type_KeyValue, ".//elem[@key='response_body']")

			if resp_header or resp_body:
				Brand_List = self.router_hpage_ptns["brands"]
				print Brand_List
				resp_page = ''.join(filter(None, [resp_header, resp_body]))

				brand_names = list()
				for item in Brand_List:
					if item in resp_page.upper():
						brand_names.append(item)
						break

				if len(brand_names) == 0:
					print 'No brand found, use unknown.'
					brand_names.append("UNKNOWN")

				q_model_sql = ""
				q_brand_sql = ""
				q_like_model_sql = ""
				device_type = self.Device_Unknown

				# Router
				device_type = self.Device_Router	
				q_model_sql = self._http_hp_query.format('TRouterLoginInfo','model', '')
				q_brand_sql = self._http_hp_query.format('TRouterLoginInfo','brand', 'limit 0,5')
				q_like_model_sql = self._http_hp_like_query.format('TRouterLoginInfo','model', 'limit 0,5')

				ret, new_brand, new_model, sql_query_result = self._query_ptn_from_db(self._Ptn_Type_Router_Http, 
					httphp_nodes[0], brand_names, q_model_sql, q_like_model_sql, sqlwrapper)
				if ret == True:
					result = self._format_dev_login_result(device_type, new_brand, new_model, [x[0] for x in sql_query_result], sqlwrapper)
					return ret, result

				# IP Camera
				# device_type = self.Device_Cam
				# q_model_sql = self._upnp_query.format('TIPCameraLoginInfo','model', '')
				# q_brand_sql = self._upnp_query.format('TIPCameraLoginInfo','brand', 'limit 0,5')
				# q_like_model_sql = self._upnp_like_query.format('TIPCameraLoginInfo','model', 'limit 0,5')

				# ret, new_brand, new_model, sql_query_result = self._query_ptn_from_db(self._Ptn_Type_Router_Http, 
				# 	httphp_nodes[0], brand_names, q_model_sql, q_like_model_sql, sqlwrapper)
				# if ret == True:
				# 	result = self._format_dev_login_result(device_type, new_brand, new_model, [x[0] for x in sql_query_result], sqlwrapper)
				# 	return ret, result

				# NAS
				# device_type = self.Device_Nas	
				# q_model_sql = self._upnp_query.format('TNASLoginInfo','model', '')
				# q_brand_sql = self._upnp_query.format('TNASLoginInfo','brand', 'limit 0,5')
				# q_like_model_sql = self._upnp_like_query.format('TNASLoginInfo','model', 'limit 0,5')

				# ret, new_brand, new_model, sql_query_result = self._query_ptn_from_db(self._Ptn_Type_Router_Http, 
				# 	httphp_nodes[0], brand_names, q_model_sql, q_like_model_sql, sqlwrapper)
				# if ret == True:
				# 	result = self._format_dev_login_result(device_type, new_brand, new_model, [x[0] for x in sql_query_result], sqlwrapper)
				# 	return ret, result
				
				return False, {}

			else:
				print 'No Http response data!'
				return False, {}

		else:
			print 'No http-homepage script id'
			return False, {}

	def _parse_wsdd_discover(self, host, sqlwrapper):

		print 'Parse WSDD Discover'
		wsdd_nodes = host.xpath(".//script[@id='wsdd-discover']")

		if not wsdd_nodes:
			print 'No wsdd-discover tag found!'
			return False, {}
		else:
			model_name = self._get_elem_data(wsdd_nodes[0], self._Type_KeyValue, ".//elem[@key='Model']")
			brand_name = self._get_elem_data(wsdd_nodes[0], self._Type_KeyValue, ".//elem[@key='Manufacturer']")
			print 'wsdd data:', model_name, brand_name

			if brand_name == "" or model_name == "":
				print 'No Manufacturer tag found!'
				return False, {}
			else:
				WSDD_IPCAM_LIST = ["FOSCAM"]

				is_found = False
				device_type = self.Device_Unknown
				q_model_sql = ""
				q_brand_sql = ""
				q_like_model_sql = ""

				for item in WSDD_IPCAM_LIST:
					if item in brand_name.upper():
						is_found = True
						device_type = self.Device_Cam
						q_model_sql = self._wsdd_query.format('TIPCameraLoginInfo','model', '')
						q_brand_sql = self._wsdd_query.format('TIPCameraLoginInfo','brand', 'limit 0,5')
						q_like_model_sql = self._wsdd_like_query.format('TIPCameraLoginInfo','model', 'limit 0,5')
						break

				if not is_found:
					print 'No brand found!'
					return False, {}

				ret, sql_query_result = self._query_result(q_model_sql, model_name, sqlwrapper)
				if ret == True:
					result = self._format_dev_login_result(device_type, brand_name, model_name, [x[0] for x in sql_query_result], sqlwrapper)
					return True, result
				else:
					return False, {}

	def _parse_model_name(self, host, sqlwrapper):

		print 'Parse model name'
		device_type = self.Device_Unknown
		upnp_nodes = host.xpath(".//script[@id='upnp-info']")

		if upnp_nodes:
			model_name = self._get_elem_data(upnp_nodes[0], self._Type_KeyValue, ".//elem[@key='modelName']")
			manufacturer = self._get_elem_data(upnp_nodes[0], self._Type_KeyValue, ".//elem[@key='manufacturer']")
			friendlyName = self._get_elem_data(upnp_nodes[0], self._Type_KeyValue, ".//elem[@key='friendlyName']")

			if model_name.find("Xbox") != -1:
				device_type = self.Device_GameConsole
			elif model_name.find("Eureka Dongle") != -1 or model_name.find("Roku") != -1:
				device_type = self.Device_MediaPlayer
			elif model_name.find("TV") != -1 or friendlyName.find("TV") != -1:
				device_type = self.Device_SmartTV
			elif model_name.find("Disc Player") != -1:
				device_type = self.Device_DiscPlayer
			elif manufacturer.find("RICOH") != -1:
				device_type = self.Device_Printer

			if device_type != self.Device_Unknown:
				result = self._format_dev_login_result(device_type, manufacturer, model_name, [], sqlwrapper)
				return True, result

		return False, {}

	def _parse_os_type(self, host, sqlwrapper):

		print 'Parse device OS type'
		device_type = self.Device_Unknown
		osmatch_nodes = host.xpath(".//osmatch")
		is_osmatch = False

		for node in osmatch_nodes:
			os_name = node.get("name")
			if os_name:
				if os_name.find("Microsoft Windows") != -1:
					device_type = self.Device_WindowsOS
					is_osmatch = True
					break
				elif os_name.find("Apple Mac") != -1:
					device_type = self.Device_MacOS
					is_osmatch = True
					break
				elif os_name.find("Apple iOS") != -1:
					device_type = self.Device_IOS
					is_osmatch = True
					break
				
				for os_class in node.xpath(".//osclass"):
					cls_type = os_class.get("type")
					if cls_type == "printer":
						device_type = self.Device_Printer
						is_osmatch = True
						break

		if is_osmatch:
			result = self._format_dev_login_result(device_type, "", "", [], sqlwrapper)
			return True, result
		else:
			#Try to parse hostname for iPhone/iPad/
			hostname_nodes = host.xpath(".//hostname")
			for node in hostname_nodes:
				host_name = node.get("name")
				if host_name:
					if host_name.find("iPhone") != -1 or host_name.find("iPad") != -1:
						device_type = self.Device_IOS
						result = self._format_dev_login_result(device_type, "", "", [], sqlwrapper)
						return True, result
			return False, {}


	def _query_result(self, s_sql, name, sql_wp):

		#q_result = sql_wp.query(s_sql, ("%"+name+"%",))
		q_result = sql_wp.query(s_sql, (name,))
		if len(q_result) > 0:
			return True, q_result
		else:
			return False, ()

	def _load_ptns(self):

		router_upnp_ptn_path = os.path.join(self._CurDir_Path, self._Router_Upnp_Ptn)
		self.router_upnp_ptns = json.loads(open(router_upnp_ptn_path).read().decode('utf-8'))

		router_hpage_ptn_path = os.path.join(self._CurDir_Path, self._Router_Hpage_Ptn)
		self.router_hpage_ptns = json.loads(open(router_hpage_ptn_path).read().decode('utf-8'))

		ipcam_upnp_ptn_path = os.path.join(self._CurDir_Path, self._IPCam_Upnp_Ptn)
		self.ipcam_upnp_ptns = json.loads(open(ipcam_upnp_ptn_path).read().decode('utf-8'))

	def _parse_ptn(self, ptn_type, nmap_node, brand_names):
		
		print 'brand_names', brand_names
		pattern = {}
		if ptn_type == self._Ptn_Type_Router_Upnp:
			pattern = self.router_upnp_ptns
		elif ptn_type == self._Ptn_Type_Router_Http:
			pattern = self.router_hpage_ptns
		elif ptn_type == self._Ptn_Type_IPCam_upnp:
			pattern = self.ipcam_upnp_ptns
		else:
			return "", []

		items = pattern["patterns"]
		upper_brands = [x.upper() for x in brand_names]
		

		for item in items:
			brand = item["brand"].upper()

			for x in upper_brands:

				if x.find(brand) == -1:
					continue
				else:
					print 'find brand:', brand
					ptns = item["ptn_list"]
					match_names = list()

					for ptn in ptns:
						key = ptn["key_name"]
						key_type = ptn["key_type"]
						regex_ptn = ptn["re_match_ptn"]
						regex_index = ptn["re_match_index"]

						if key and key_type and regex_ptn and regex_index >= 0:
							info = self._get_elem_data(nmap_node, key_type, key)
							m = re.search(regex_ptn, info)
							if m:
								print 'matched!'
								#We need to use new brand name to flush UNKNOWN
								if ptn.get("new_brand"):
									brand = ptn["new_brand"]
									print 'update brand:', brand
								match_names.append(m.group(regex_index))

					if len(match_names) > 0:
						return brand, match_names
					else:
						print 'match_names size is 0'
						return "", []

		return "", []

	def parse_vul_defpwd(self, filename):

		vuls = list()

		flog = open(filename)

		if flog:
			if not self._validate_xml(filename):
				flog.close()
				return vuls

			contents = flog.read()
			xml_root = etree.fromstring(contents)

			hosts = xml_root.xpath(".//host")

			for host in hosts:
				print 'parse 1 host'
				httpauth_nodes = host.xpath(".//script[@id='tm-http-auth']")
				if httpauth_nodes:

					for table in httpauth_nodes[0]:
						print 'parse 1 children'
						status = self._get_elem_data(table, self._Type_KeyValue, ".//elem[@key='check_status']")
						if status != 'true':
							print 'check_status is not true, skip this host!'
							continue

						result = dict()

						ipaddr = ""
						ipaddr_nodes = host.xpath(".//address[@addrtype='ipv4']")
						if ipaddr_nodes:
							ipaddr = ipaddr_nodes[0].get("addr")
						macaddr = ""
						macaddr_nodes = host.xpath(".//address[@addrtype='mac']")
						if macaddr_nodes:
							macaddr = macaddr_nodes[0].get("addr")

						username = self._get_elem_data(table, self._Type_KeyValue, ".//elem[@key='username']")
						password = self._get_elem_data(table, self._Type_KeyValue, ".//elem[@key='password']")
						path = self._get_elem_data(table, self._Type_KeyValue, ".//elem[@key='path']")

						result[self._IP_KEY] = ipaddr
						result[self._MAC_KEY] = macaddr
						result[self._CHECK_STATUS_KEY] = status
						result[self._USER_NAME_KEY] = username
						result[self._PASS_WORD_KEY] = password
						result[self._PATH_KEY] = path
						
						vuls.append(result)

			flog.close()

		else:
			print 'open file failed'

		return vuls


if __name__ == '__main__':


	# conn = MySQLdb.connect(host="localhost", user="root", passwd="mac8.6", db="iotdb")
	# cur = conn.cursor()
	# name = '2'
	# cur.execute("""UPDATE test SET brand=%s WHERE model = %s""", ('333', name))
	# conn.commit()
	# #cur.execute("SELECT default_ip_address, default_user_name, default_password  FROM TRouterLoginInfo limit 0,10")
	# #cur.execute(_upnp_query, ('model', "'%%TL-WR841N%%'"))
	# cur.execute("SELECT default_ip_address FROM TRouterLoginInfo  WHERE %s like %s limit 0,10", ("model", "%"+"TL-WR841N"+"%",))
	# row = cur.fetchall()
	# print row

	#sys.exit(1)
###################################################################################################
	curpath = os.path.dirname(os.path.abspath(__file__))
	LogUtil.initialize(LogUtil.DEBUG, curpath, 'dring')
 
	LogUtil.getlogger().info('start to parse xml')
 
	p = InteliParser()
	p.Parse(InteliParser.Parser_Nmap, '/home/zjg/workspace/Trend0518/api/impl/testhp.xml')
	
	