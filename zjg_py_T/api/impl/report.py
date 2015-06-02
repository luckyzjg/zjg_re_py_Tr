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
import time
from util.logutil import LogUtil

MODEL_REPORT_FILE =  'Model_Report.csv'

def nmap_list(dia_folder,failhost_dir,nmap_name):
    xmlfoldernum = 0
    contents =[]
    devicesnum = 0
    win_num = 0
    app_num = 0
    hostnum = 0
    unknown_num = 0
    others_num =0
    identify_num = 0
    result =''
    ip_dir = {'192.168.1.1':0,'192.168.0.1':0,'192.168.1.254':0,
    '10.0.0.1':0,'192.168.2.1':0}
    ipnum = 0
    p = InteliParser()
    #failhost_dir =os.path.join(path,nmap_name+'-failhost/')
    if os.path.exists(failhost_dir):
        shutil.rmtree(failhost_dir)
        os.mkdir(failhost_dir)
    else:
        os.mkdir(failhost_dir)
    #os.mkdir(failhost_dir)
    xml_dir  = os.path.join(dia_folder,'nmap_output')
    for folder in os.listdir(xml_dir):

        folderDir = os.path.join(xml_dir,folder)
        
        for subfile in os.listdir(folderDir):

            if subfile.startswith('nmap_xml'):
                xmlfoldernum +=1
                xmlDir = os.path.join(folderDir,subfile)
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
                    if item['device_category'] == 0:
                        unknown_num += 1
                    elif item['device_category'] == 12:
                        others_num +=1
                    else:
                        identify_num +=1



                    if item['device_category'] == 4:
                        win_num +=1
                    if item['device_category'] == 5:
                        app_num +=1
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
                            
                            # if item['device_category'] in [1,2,3]:
                            #     item['device_brand'] = item['device_brand'].replace(',','.')   
                        if ',' in item['device_brand']:
                            item['device_brand'] = item['device_brand'].replace(',','.')

                        input_info = '{0},{1},{2},{3},{4},{5},{6}'.format(xmlDir,
                        item['host_ip'], item['host_mac'], item['device_model'],item['device_category'],item['device_brand'],
                        str(item['default_login_info']))
                        wfile.write(input_info)
                        wfile.write('\n')

                    all_info = ''
                    for elem in item['default_login_info']:
                        elem = elem.replace(',',' ')
                        all_info+=elem
                        item['default_login_info'] = all_info

                                
                    if ',' in item['device_model']:
                        item['device_model'] = item['device_model'].replace(',','.')
                            
                    if item['device_category'] in [1,2,3]:
                        item['device_brand'] = item['device_brand'].replace(',','.')   
                        # if ',' in item['device_brand']:
                        #     item['device_brand'] = item['device_brand'].replace(',','.')

                    all_input_info = '{0},{1},{2},{3},{4},{5},{6}'.format(xmlDir,
                    item['host_ip'], item['host_mac'], item['device_model'],item['device_category'],item['device_brand'],
                    str(item['default_login_info']))
                    wfile2.write(all_input_info)
                    wfile2.write('\n')

                    
                if flag == True:
                    shutil.copy(xmlDir,failhost_dir)
                    

    wfile.write('\n')
    result =('xml_folder_num:'+str(xmlfoldernum)+'\n')
    result  +=("hostnumber: "+str(hostnum) +'\n')

    result +=("Win_number :"+str(win_num)+'\n')
    result +=("App_number :"+str(app_num)+'\n')
    result +="devices number:" + str(devicesnum)+'\n'
    wfile.write(result)
    wfile.write('analyzed logs :'+str(identify_num)+'\n')

    wfile.write('devices category detection rate: '+str("%.4f%%" % (identify_num /hostnum*100))+'\n')
    wfile.write('device brand detection rate: '+str("%.4f%%" % ((identify_num+others_num) /hostnum*100))+'\n')

    wfile.write("Model detection rating for non-pc devices : "
     + str("%.4f%%" % (devicesnum/(hostnum-win_num-app_num)*100))+'\n')

    wfile.write("Model detection rating for router : "+str("%.4f%%" % ((identify_num/xmlfoldernum)*100))+"\n")
    

    wfile.write('\n'+'IP_Addr_Num :'+str(ipnum)+'\n')
    for elem in ip_dir.keys():
        wfile.write(elem + ':  '+str(ip_dir[elem])+'\n')
    wfile.write('\n')
    
    

    wfile.write('devices / IP:  ' + str("%.4f%%" % (devicesnum/ipnum*100))+'\n' )
    wfile.write('devicesnum / scanner_family_num:  '+str("%.4f%%" % (devicesnum/xmlfoldernum*100))+'\n')
    
    
    print devicesnum
    result = [devicesnum,xmlfoldernum]
    print result

    result_list =[identify_num,str("%.4f%%" % ((identify_num+others_num) /hostnum*100)),
    str("%.4f%%" % (identify_num /hostnum*100)),
    str("%.4f%%" % (devicesnum/(hostnum-win_num-app_num)*100)),
    str("%.4f%%" % ((devicesnum/xmlfoldernum)*100))]
    return result_list
    
    


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
    failcount = 0
    
    for folder in os.listdir(path):
        failcount +=1

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

    print failcount
    #time.sleep(10)

    modle_list = sorted(model_dict1.iteritems(),key=operator.itemgetter(1),reverse=True)
    print modle_list
    for elem in modle_list:
        key = list(elem)[0]
        wfile1.write(key +','+str(model_dict1[key])+','+model_dict2[key]+'\n')

    return failcount


def modle_test(path,nmap_name):

    unique_modle_file = os.path.join(path, MODEL_REPORT_FILE)
    dia_folder = os.path.join(path,'diamond_report')
    
    shutil.move(unique_modle_file,dia_folder)
    
    rfile = open(os.path.join(dia_folder, MODEL_REPORT_FILE),'r+')
    content = rfile.readlines()
    rfile.close()

    modle_list =[]
    add_list = []
    for index in content:
        modle = index.split(',')[0]
        modle_list.append(modle)
    print content

    wfile = open(os.path.join(dia_folder, MODEL_REPORT_FILE),'w+')
    currenfile = open(os.path.join(dia_folder,nmap_name+'-logoutput.csv'),'r+').readlines()
    filedate = nmap_name
    
    for item in currenfile:
        #print item
        if item.startswith('/home/'):
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

    rfile = open(os.path.join(dia_folder, MODEL_REPORT_FILE),'r')
    content = rfile.readlines()
    unique_model_num =len(content)
    rfile.close()

    new_unique_model_file = os.path.join(dia_folder, MODEL_REPORT_FILE)
    shutil.copy(new_unique_model_file,path)
    return unique_model_num

def xmllogsum(nmap_name,xml_log_num):
    
    filecontent = open(os.path.join(path,'lognum.txt'),'r').readlines()
    last_time = filecontent[0].split('=')[1]
    lognum = int(filecontent[1].split('= ')[1])
    have_analied = int(filecontent[2].split('= ')[1])
    if last_time < nmap_name:
        
#         new_xml_num = lognum+xml_folder_num[0]
#         new_analied_num =have_analied+xml_folder_num[1]
        wfile3 = open(os.path.join(path,'lognum.txt'),'w')
        wfile3.write('current_time ='+ nmap_name+'\n')
#         wfile3.write("collected_logs = "+str(new_xml_num)+'\n')
#         wfile3.write("analyzed_logs = "+str(new_analied_num)+'\n')
        wfile3.close()

#         wfile.write("\ncollected_logs = "+str(new_xml_num)+'\n')
#         wfile.write("analyzed_logs= "+str(new_analied_num)+'\n')
    else:
        wfile.write("\ncollected_logs = "+str(lognum)+'\n')
        wfile.write("analyzed_logs= "+str(have_analied)+'\n')



def report_update(path, nmap_name, result):
    path1 = os.path.join(path,'DRScanner_Analysis_Report_Weekly.csv')
    rfile  = open(path1,'r')
    content  = rfile.readlines()
    length= len(content)
    print length
    
    rfile.close()
    analy_count = content[length-1].split(',')[5]
    current_count = str(int(analy_count)+result[0])
    
    current_time = time.strftime("%Y-%m-%d")
    input_info = '{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10}'.format(current_time,nmap_name,
    'unknown','unknown','unknown',
    result[0],result[1],
    result[2],result[-1],
    result[3],result[4])

    date_dir = {}
    for (num,elem1) in enumerate(content):   
        list1 = elem1.split(',')
        if list1[1] not in date_dir.keys():
            date_dir[list1[1]] = num

    print date_dir
    if nmap_name in date_dir.keys():
        del content[date_dir[nmap_name]]
        content.append(input_info)
    else:
        content.append(input_info)
        
    wfile4  = open(path1,'w+')


                        
    wfile4.writelines(content)
    wfile4.write('\n')
    wfile4.close()



if __name__ == '__main__':  
    nmap_name = ''
    failcount = 0
    result_list= []
    path = os.getcwd()
    os.chdir(path)
    dia_folder = os.path.join(path,'diamond_report')
    
    if os.path.exists(dia_folder):
        shutil.rmtree(dia_folder)
        os.mkdir(dia_folder)
    else:
        os.mkdir(dia_folder)
    for index in os.listdir(path):
        if index.endswith('tar.gz'):
            nmap_name = index.split('.tar')[0]
            
            os.system('tar -zxvf'+index)
    
    shutil.move('nmap_output',dia_folder)

    success_model_list = os.path.join(dia_folder,nmap_name+'-logoutput.csv')
    all_model_list = os.path.join(dia_folder,'all-'+nmap_name+'-logoutput.csv')
    wfile = open(success_model_list,'w+')
    wfile2 = open(all_model_list,'w+')
    failhost_dir = os.path.join(dia_folder,nmap_name+'-failhost')
    
    
    result_list = nmap_list(dia_folder,failhost_dir,nmap_name)
    

    fail_model_list = os.path.join(dia_folder,'fail-'+nmap_name+'-logoutput.csv')

    wfile1 = open(fail_model_list,'w+')
    failcount = fail_host_modelname(failhost_dir)

    #xmllogsum(nmap_name,xml_folder_num)

    
    wfile.close()
    wfile2.close()
    wfile1.close()
    
    unique_model_num = modle_test(path,nmap_name)
    result_list.append(unique_model_num)
    
    print result_list
    report_update(path, nmap_name, result_list)
    


