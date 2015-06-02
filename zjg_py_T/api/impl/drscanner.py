# -*- coding: utf-8 -*-
from __future__ import division
from parser import InteliParser
import re
from lxml import etree
import MySQLdb
import sys
import os
import json
import shutil
import operator

from util.logutil import LogUtil

def DRS_list(path,nmap_name):
    xmlfoldernum = 0
    contents =[]
    devicesnum = 0
    win_app_num = 0
    hostnum = 0
    result =''
    ip_dir = {'192.168.1.1':0,'192.168.0.1':0,'192.168.1.254':0,
    '10.0.0.1':0,'192.168.2.1':0}
    ipnum = 0
    p = InteliParser()
    failhost_dir = '/home/jerry/Desktop/'+nmap_name+'-failhost/'
    os.mkdir(failhost_dir)

    for folder in os.listdir(path):
      
        xmlfoldernum +=1
        xmlDir = os.path.join(path,folder)
        print xmlDir
                

        contents = p.Parse(InteliParser.Parser_Nmap, xmlDir)
                
        hostnum +=len(contents)
        flag = True
        for item in contents:
            item['device_model']=item['device_model'].strip()
            if len(item['device_model']) < 0:
                continue
            if item['host_ip'] in ip_dir.keys():
                ipnum+=1
                ip_dir[item['host_ip']]+=1                   
            if item['device_category'] in [4,5]:
                win_app_num +=1
            if item['device_category'] in [1,2,3]:
                flag = False
                print flag
                devicesnum+=1
            logininfo = ''
            for elem in item['default_login_info']:
                elem = elem.replace(',',' ')
                logininfo +=elem
            item['default_login_info'] = logininfo

                            
            if ',' in item['device_model']:
                item['device_model'] = item['device_model'].replace(',','.')
                            
            if item['device_category'] in [1,2,3]:
                item['device_brand'] = item['device_brand'].replace(',','.')

            input_info = '{0},{1},{2},{3},{4},{5},{6}'.format(xmlDir,
            item['host_ip'], item['host_mac'], item['device_model'],item['device_category'],item['device_brand'],
            str(item['default_login_info']))
            wfile.write(input_info)
            wfile.write('\n')
                    
        if flag == True:
            shutil.copy(xmlDir,failhost_dir)
                    

    wfile.write('\n')
    result =('xml_folder_num:'+str(xmlfoldernum)+'\n')
    result  +=("hostnumber: "+str(hostnum) +'\n')

    result +=("pc and Apple :"+str(win_app_num)+'\n')
    result +="devices number:" + str(devicesnum)+'\n'
    wfile.write(result)
    wfile.write('\n'+'IP_Addr_Num:'+str(ipnum)+'\n')
    for elem in ip_dir.keys():
        wfile.write(elem + ':  '+str(ip_dir[elem])+'\n')
    wfile.write('\n')
    wfile.write("devices / (host - pc_app): " + str("%.4f%%" % (devicesnum/(hostnum-win_app_num)*100))+'\n')
    wfile.write('devices / IP:  ' + str("%.4f%%" % (devicesnum/ipnum*100))+'\n' )
    wfile.write('devicesnum / xmlfiles:  '+str("%.4f%%" % (devicesnum/xmlfoldernum*100))+'\n')
    print devicesnum
    result = [devicesnum,xmlfoldernum]
    print result




def _get_elem_data(node, type, path_name):
        if node is not None:
            nodes = node.xpath(path_name)
            if type == 1:
                return nodes[0].text if nodes and nodes[0].text else ""
            else:
                return ''.join(nodes[0].itertext()) if nodes else ""

        return ""
    
def fail_host_modelname(path):

    model_dict1 = {}
    model_dict2 ={}
    modle_list = []
    for folder in os.listdir(path):
        folderDir = os.path.join(path,folder)

        flog = open(folderDir)
        if flog:
            is_valid = True

            try:
                etree.parse(folderDir)
            except:
                is_valid = False

            if is_valid == False:
                print 'invalid xml file'
                continue


        contents = flog.read()
        xml_root = etree.fromstring(contents)

        hosts = xml_root.xpath(".//host")
    
        for host in hosts:
            upnp_nodes = host.xpath(".//script[@id='upnp-info']")
            for upnp_node in upnp_nodes:
                if upnp_node:
                    model_name = _get_elem_data(upnp_node, 1, ".//elem[@key='modelName']")
                    if model_name not in model_dict1.keys():
                    	#print model_name
                    	#modle_list.append(model_name)
                        model_dict1[str(model_name)] = 1
                        model_dict2[str(model_name)] = folder
                    else:
                        model_dict1[str(model_name)]+=1
                        model_dict2[str(model_name)] += '  ;  '+folder

    
    modle_list = sorted(model_dict1.iteritems(),key=operator.itemgetter(1),reverse=True)
    print modle_list
    for elem in modle_list:
        key = list(elem)[0]
        wfile1.write(key +','+str(model_dict1[key])+','+model_dict2[key]+'\n')


def modle_test(path):
    rfile = open('/home/hadoop/Desktop/Modle_Report.csv','r+')
    content = rfile.readlines()
    rfile.close()
    modle_list =[]
    add_list = []
    for index in content:
        modle = index.split(',')[0]
        modle_list.append(modle)
    print content

    wfile = open('/home/hadoop/Desktop/'+'Modle_Report.csv','w+')
    currenfile = open(path,'r+').readlines()
    filedate = path.split('-logoutput')[0].split('Desktop/')[1]
    
    for item in currenfile:
        #print item
        if item.startswith('/home/hadoop/'):
            e_list = item.split(',')
            elem = e_list[3]
            if elem not in modle_list and len(elem)!= 0:
                modle_list.append(elem)
                
                input_info = '{0},{1},{2},{3},{4}'.format(elem,e_list[4],e_list[5],filedate,'\n')
                
                content.append(input_info)
               
            else:
                continue
    # print add_list
    # content = content.extend(add_list)
    print content
    wfile.writelines(content)
    wfile.close()



if __name__ == '__main__':
	    
    nmap_name = 'DRScanner'
    
    
    

    wfile = open('/home/jerry/Desktop/'+nmap_name+'-logoutput.csv','w+')
    
    Dsrdir = '/home/jerry/Desktop/11/allinone/'
    #nmap_list(nmapDir,nmap_name)
    DRS_list(Dsrdir,'dsrfolder')
    
    #get_host_num(nmapDir)
    
    wfile.close()
    wfile1 = open('/home/jerry/Desktop/fail-'+nmap_name+'-logoutput.csv','w+')
   
    Dsr_fail_dir = '/home/jerry/Desktop/' + 'dsrfolder'+'-failhost'
    fail_host_modelname(Dsr_fail_dir)
    wfile1.close()
    
    modle_test('/home/jerry/Desktop/'+nmap_name+'-logoutput.csv')

