import re
import shutil
import os
import os.path
import csv
from util.ConfigWrapper import ConfigWrapper



cfg_wrp = ConfigWrapper()
originfile_path=cfg_wrp.config.get('CheckModel','originfile_path')
all_xml_path=cfg_wrp.config.get('CheckModel','all_xml_path')
csvfile_path_already=cfg_wrp.config.get('CheckModel','csvfile_path_already')
all_xml_keyword_path=cfg_wrp.config.get('CheckModel','all_xml_keyword_path')
pattern="^nmap_xml"
def dealwithfile():
    str_path=list()
    f=file(csvfile_path_already)
    reader=csv.reader(f)
    for row in reader:
        i=row[0].rfind('/')+1
        fix=row[0][i:]
        str_path.append(fix)
    print str_path
    for parent,dirnames,filenames in os.walk(originfile_path):
        for filename in filenames:
            m=re.search(pattern, filename)
            if m:
                src=parent+"/"+filename
                dst=all_xml_path+'/'+filename
                for filename_e in str_path:
                    if filename==filename_e:
                        print filename
                        shutil.copy(src, dst)              
# dealwithfile()    

def dealwith_keyword():
    count=0
    for parent,dirnames,filenames in os.walk(all_xml_path):
        for filename in filenames:
            file_path=all_xml_path+'/'+filename
            f=open(file_path)
            read=f.read()
            if "upnp-info" in read:
                count+=1
                shutil.copy(file_path, all_xml_keyword_path)
                print count
    
# dealwith_keyword()    
def dealwith_row():
    str_1="<elem key=\"friendlyName\">"
    str_2="<elem key=\"manufacturer\">"
    str_3="<elem key=\"modelDescription\">"
    str_4="<elem key=\"modelName\">"
    str_5="<elem key=\"modelNumber\">"
    pre_path='/home/zjg/Documents/c/all_keyword_0520'
#     pre_path='/home/zjg/Documents/c/xml_path'
    txt_path='/home/zjg/Documents/c/info.txt'
    count=0
    for parent,dirnames,filenames in os.walk(pre_path):
        for filename in filenames:
            fe=open(txt_path,'a')
            fe.write(filename+'\r\n')
            fe.close()
            file_path=pre_path+'/'+filename
            f=open(file_path,'r')
            while True:
                line=f.readline()
                if line:
                    count+=1
                    if (str_1 in line) or str_2 in line or str_3 in line or str_4 in line or str_5 in line:
                        fe1=open(txt_path,'a')
                        fe1.write(line)
                        fe1.close()
                else:
                    break
            print count       
dealwith_row()            
            