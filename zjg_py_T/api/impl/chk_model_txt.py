import os
import time
import platform
import json
import re
import csv
import xlrd
from util.MysqlWrapper import MysqlWrapper
from util.ConfigWrapper import ConfigWrapper
from MySQLdb.constants.ER import YES
from pyExcelerator.Workbook import Workbook


cfg_wrp = ConfigWrapper()
total_modeltxt_path=cfg_wrp.config.get('CheckModel','modeltxt_path')
router_js_path=cfg_wrp.config.get('CheckModel','router_js_path')
read_path=cfg_wrp.config.get('CheckModel','read_path')
csvfile_path=cfg_wrp.config.get('CheckModel','csvfile_path')
patternR="^Roku"
patternS="^Sonos"
patternUN="^UN"
patternTX="^TX-"
patternUE="^UE"
patternSEC="^SEC"
patternSam="^Samsung"
patternKodak="^KODAK "
patternDcs="^DCS-"
patternAXIS="^AXIS "
patternAfri="^Aficio "
patternMP="^MP "
patternBD="^BD-"
patternMedia="^Media "
patternTS="^TS-"
patternTV="^TV-"
patternHIKV="^HIKVISION "
patternRead="^--"


def parse_js():
    q_model_sql='''SELECT login_info_id from TRouterLoginInfo WHERE model = %s'''
    db_wrapper=DBconn()
    create_classification_file(router_js_path)
    models_js=json.loads(open(router_js_path).read().decode('utf-8'))
    for model_brand in models_js:
        models=model_brand["models"]
        for models_i in models:
            model_single=models_i["model"]
            model_single_en=model_single.encode('utf-8')
            try:
                result=db_wrapper.query(q_model_sql, (model_single_en,))
                if result:
                    fe=open(_exist_modeltxt_path,'a')
                    fe.write(model_single_en+'\r\n')
                    fe.close()
                else:
                    fne=open(_notexist_modeltxt_path,'a')
                    fne.write(model_single_en+'\r\n')
                    fne.close()
            except:
                print model_single_en
                print type(model_single_en)
                
def count_read():
    count=0
    f=open(read_path,'r')
    while True:
        line=f.readline()
        keyword=line.strip('\r\n')
        if line:
            m=re.match(patternRead,keyword)
            if m:
                count+=1
        else:
            break
    print count
                       
            

        
            
        
    

def readTxt():
    f=open(total_modeltxt_path,'r')
    q_model_sql='''SELECT login_info_id from TRouterLoginInfo WHERE model = %s'''
    db_wrapper=DBconn()
    create_classification_file(total_modeltxt_path)
#     a=db_wrapper.query(q_model_sql, ('11WA-321A',))
#     print a 
    while True:
        line=f.readline()
        print line
        keyword=line.strip('\r\n')
        if line:
            if len(line)==0:
                print "This line is blank!"
                break
            else:
                result=db_wrapper.query(q_model_sql, (keyword,))
                if result:
                    fe=open(_exist_modeltxt_path,'a')
                    fe.write(line)
                    fe.close()
                else:
                    print _notexist_modeltxt_path
                    flag=_parse_ptn(keyword)
                    if flag==True:
                        fe=open(_exist_modeltxt_path,'a')
                        fe.write(line)
                        fe.close()
                    else:
                        if re.findall(patternR,keyword) or re.findall(patternS,keyword) or "Network Camera" in keyword \
                        or "Windows Media" in keyword or "KODAK ESP" in keyword or " series" in keyword \
                        or " Printer" in keyword or(re.findall(patternUN,keyword) and len(keyword)==9) \
                        or (re.findall(patternUN,keyword) and len(keyword)==10) or "Aficio MP" in keyword \
                        or "Roku TV" in keyword or "Print Server" in keyword or "Media Server" in keyword \
                        or (re.findall(patternTX,keyword) and len(keyword)==9) \
                        or (re.findall(patternTX,keyword) and len(keyword)==8) \
                        or (re.findall(patternUE,keyword) and len(keyword)==10) \
                        or (re.findall(patternUE,keyword) and len(keyword)==9) \
                        or (re.findall(patternSEC,keyword) and len(keyword)==15) \
                        or ("XP-" and " Series" in keyword) or re.findall(patternSam,keyword) \
                        or re.findall(patternKodak,keyword) or re.findall(patternDcs,keyword) \
                        or re.findall(patternAXIS,keyword) or re.findall(patternAfri,keyword) \
                        or re.findall(patternMP,keyword) or re.findall(patternBD,keyword) \
                        or re.findall(patternMedia,keyword) or re.findall(patternTS,keyword) \
                        or re.findall(patternTV,keyword) or ("Access Point" in keyword) \
                        or re.findall(patternHIKV,keyword):
                            fnoneed=open(_noneed_modeltxt_path,'a')
                            fnoneed.write(line)
                            fnoneed.close()
                        else:
                            fne=open(_notexist_modeltxt_path,'a')
                            fne.write(line)
                            fne.close()
        else:
            break

def DBconn():
    db_name = cfg_wrp.config.get('Database', 'iotdb_name')
    db_host = cfg_wrp.config.get('Database', 'host')
    db_user = cfg_wrp.config.get('Database', 'user')
    db_passwd = cfg_wrp.config.get('Database', 'passwd')
    _db_wrapper = MysqlWrapper(db_host, db_name, db_user, db_passwd)
    return  _db_wrapper  


def create_classification_file(file_path):
    global _exist_modeltxt_path
    global _notexist_modeltxt_path
    global _noneed_modeltxt_path
    str_time=time.strftime('%Y-%m-%d-%H-%M-%S',time.localtime(time.time()))
    i=file_path.rfind('/')+1
    pre=file_path[:i]
    _exist_modeltxt_path=pre+"existmodel"+str_time+".txt"
    _notexist_modeltxt_path=pre+"notexistmodel"+str_time+".txt"
    _noneed_modeltxt_path=pre+"noneedmodel"+str_time+".txt"
    _csv_modeltxt_path=pre+"csvmodel"+str_time+".txt"
    chk_exist_classificationfile(_exist_modeltxt_path)
    chk_exist_classificationfile(_notexist_modeltxt_path)
    chk_exist_classificationfile(_noneed_modeltxt_path)
    

def chk_exist_classificationfile(path):
    chk=os.path.exists(path)
    if chk==True:
        f=open(path,'w')
        f.close()
    else:
        f=open(path,'w')
        f.close()
        
def chk_platform_newline():
    _platform=platform.system()
    print _platform
    if _platform=="Windows":
        newline='\r\n'
    if _platform=="Linux":
        newline='\n'
    return newline

_CurDir_Path = os.path.dirname(os.path.abspath(__file__))
_Router_Upnp_Ptn = "router_upnp_copy.ptn"
def _parse_ptn(strValue):
    router_upnp_ptn_path = os.path.join(_CurDir_Path, _Router_Upnp_Ptn)
    router_upnp_ptns = json.loads(open(router_upnp_ptn_path).read().decode('utf-8'))
    pattern = router_upnp_ptns
    items = pattern["patterns"]
    for item in items:
        ptns = item["ptn_list"]
        for ptn in ptns:
            key = ptn["key_name"]
            key_type = ptn["key_type"]
            regex_ptn = ptn["re_match_ptn"]
            regex_index = ptn["re_match_index"]
            if key and key_type and regex_ptn and regex_index >= 0:
                m = re.search(regex_ptn, strValue)
                if m:
                    return True
                else:
                    continue
    return False            
                    
def read_csv():
    str_time=time.strftime('%Y-%m-%d-%H-%M-%S',time.localtime(time.time()))
    i=csvfile_path.rfind('/')+1
    pre=csvfile_path[:i]
    _csv_modeltxt_path=pre+"csvmodel"+str_time+".txt"
    _csv_modelcreate_path=pre+"csvmodel"+str_time+".csv"
    f=file(csvfile_path)
    reader=csv.reader(f)
    for row in reader:
        if row[4]=='3' and row[3]=='':
            csvfile = file(_csv_modelcreate_path, 'ab')
            writer = csv.writer(csvfile)
            writer.writerow([row[0],row[1],row[2],row[5]])
            csvfile.close()
#             fneed=open(_csv_modeltxt_path,'a')
#             fneed.write(row[0]+"|"+row[1]+"|"+row[2]+"|"+row[5]+"\r\n")
#             fneed.close()
            print row[1]
        else:
            continue
            
def read_xls():
    db_wrapper=DBconn()
    str_time=time.strftime('%Y-%m-%d-%H-%M-%S',time.localtime(time.time()))
    xlsfile_path='/home/zjg/Documents/xls/routers_all_new.xls'
    i=xlsfile_path.rfind('/')+1
    pre=xlsfile_path[:i]
    xls_notinDB_path=pre+"notinDB"+str_time+".xls"
    bk=xlrd.open_workbook(xlsfile_path)
    try:
        sh=bk.sheet_by_name("Sheet1")
    except:
        print "no sheet in %s named Sheet1" % xls_notinDB_path
    num_rows=sh.nrows
    num_cols=sh.ncols
    print "nrows %d, ncols %d" % (num_rows,num_cols)
    global m
    m=0
    w=Workbook()
    ws = w.add_sheet('notinDB')
    q_model_sql='''SELECT login_info_id from TRouterLoginInfo WHERE model = %s'''
    for i in range(0,num_rows):
        brand=sh.cell_value(i,0)
        keyword=sh.cell_value(i,1)
        print keyword
        result=db_wrapper.query(q_model_sql, (keyword,))
        if result:
            print "YES"
        else:
            print "No"  
            ws.write(m,0,brand)
            ws.write(m,1,keyword)
            w.save(xls_notinDB_path)
            m+=1
               
                        
# def dele_newline_flag(keyword):
#     winf='\r\n'
#     linuxf='\n'
#     if winf in keyword:
#         keyword.strip(winf)
#     if linuxf in keyword:
#         keyword.strip(linuxf) 
#     print keyword
#     return keyword   


#dele_newline_flag("Windows Media Player Sharing\r\n")
#chk_platform_newline()
#create_classification_file()                           
#readTxt()     
# parse_js()  
# count_read()     
# read_csv()  
read_xls() 
            