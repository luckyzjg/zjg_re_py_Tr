# -*- coding: utf-8 -*-
import sys
import os
import json
import hashlib
import urllib2

sys.path.append("../..")
from util.MysqlWrapper import MysqlWrapper
from util.logutil import LogUtil
from util.ConfigWrapper import ConfigWrapper
from parser import InteliParser

cfg_wrp = ConfigWrapper()
db_name = cfg_wrp.config.get('Database', 'iotdb_name')
db_host = cfg_wrp.config.get('Database', 'host')
db_user = cfg_wrp.config.get('Database', 'user')
db_passwd = cfg_wrp.config.get('Database', 'passwd')

db_wrapper = MysqlWrapper(db_host, db_name, db_user, db_passwd)
CurDir_Path = os.path.dirname(os.path.abspath(__file__))
XML_Dir = os.path.join(CurDir_Path, 'xmldir')

xml_url = 'http://10.1.196.20/drserver/api/nmaplog/'

pr = InteliParser()



def parse_device_info():

	devices = json.loads(open(os.path.join(CurDir_Path, 'all_in_one.json')).read().decode('utf-8'))

	dev_fw = open('iot_def_pwd.csv', 'w')

	for device in devices:

		log_url = xml_url + str(device["TargetSessionID"])

		try:

			xmlfile = os.path.join(XML_Dir, str(device["TargetSessionID"]) + ".xml")

			if not os.path.isfile(xmlfile):
				req = urllib2.Request(log_url)
				res = urllib2.urlopen(req)
				html = res.read()
				wfile = open(xmlfile, 'w')
				wfile.write(html)
				wfile.close()
			
			else:
				print 'file is downloaded, just read it.'

			print 'Start to parse file', xmlfile
			items = pr.Parse(InteliParser.Parser_Nmap, xmlfile)

			for item in items:

				if item['host_ip'] == device['TargetIPv4Addr']:

					dev_model = item['device_model']
					dev_brand = item['device_brand'].replace(',', ' ')
					dev_cat = item['device_category']

					if  dev_model != "":

						device_info = ""
						device_info = dev_brand + ","

						device_info = device_info + dev_model + ","
						device_info = device_info + str(dev_cat) + ","

						device_info = device_info + device['SourceIPv4Addr'] + ","
						credential = device['default_login_info']['login_check']['credential']
						uname_key = credential[0]['username_key']
						pwd_key = credential[0]['password_key']

						device_info = device_info + credential[0][uname_key] + ","
						device_info = device_info + credential[0][pwd_key] + ","
						device_info = device_info + device['default_login_info']['login_check']['path'] + ","

						log_id = store_db_login(json.dumps(device['default_login_info']), dev_model)
						device_info = device_info + str(log_id) + ","
						
						device_info = device_info + str(device["TargetSessionID"]) + ".xml"
						device_info = device_info + "\n"

						print 'Write 1 record to file'
						dev_fw.write(device_info)

		except urllib2.HTTPError, e:
			print 'Urllib2 failed with error code %s' %e.code
		except:
			continue

	dev_fw.close()


def store_db_login(login_info, model):

	m = hashlib.sha1()
	m.update(login_info)
	login_sha1 = m.hexdigest()
	print login_sha1


	#insert_sql = 'INSERT IGNORE INTO TIOTLoginInfo (login_info, login_info_sha1) VALUES(%s, %s)'
	insert_sql = '''INSERT INTO TIOTLoginInfo (login_info, login_info_sha1) SELECT * FROM (SELECT %s, %s) AS tmp 
	WHERE NOT EXISTS (SELECT login_info_sha1 FROM TIOTLoginInfo WHERE login_info_sha1 = %s) LIMIT 1'''

	db_wrapper.execute(insert_sql, (login_info, login_sha1, login_sha1))
	
	query_sql = 'SELECT id from TIOTLoginInfo where login_info_sha1 = %s'
	result = db_wrapper.query(query_sql, (login_sha1,))
	log_id = result[0][0]
	print log_id

	if log_id > 0:
		print 'update login id with model'
		update_sql = '''UPDATE TRouterLoginInfo set login_info_id = %s where model = %s'''
		db_wrapper.execute(update_sql, (str(log_id), model))
		print 'finish update database'

	return log_id

parse_device_info()