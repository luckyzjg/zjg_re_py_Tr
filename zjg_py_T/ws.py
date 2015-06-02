from flask import Flask, current_app, request
import logging, json
from flask import jsonify

#API import
from api.Scan import api_Scan
from api.Cancel import api_Cancel
from api.GetProgress import api_GetProgress
from api.GetResult import api_GetResult

wsapp = Flask(__name__)
wsapp.debug = True

config = {
    "version": "v1.0",
    "base_path": "/api/diamondring/v1.0",
}

api_map = {
    "scan": {
        "api_path": config["base_path"] + "/Scan",
        "api_handler": api_Scan
    },
    "cancel": {
        "api_path": config["base_path"] + "/Cancel",
        "api_handler": api_Cancel
    },
    "progress": {
        "api_path": config["base_path"] + "/GetProgress",
        "api_handler": api_GetProgress
    },
    "result": {
        "api_path": config["base_path"] + "/GetResult",
        "api_handler": api_GetResult
    }
}

def RequestDispatcher(api_key, param_json):
    ret_value = 0
    try:
        ret_value = api_map[api_key]["api_handler"](wsapp, param_json)
    except:
        ret_value = "Exception happened in " + api_key + " with " + jsonify(param_json)
        wsapp.logger.debug(ret_value)
    return ret_value

def RequestHandler(api_key):
    if api_key in api_map:
        wsapp.logger.debug(api_map[api_key]["api_path"])
        param = None
        if request.method == 'GET':
            param = request.args
        elif request.method == 'POST':
            param = request.json
        wsapp.logger.debug(param)
        return RequestDispatcher(api_key, param)
    else:
        return "No " + api_key + " interface"

@wsapp.route('/')
def index():
    return '''
            <html>
            <head>
            <title>Diamond Ring Service running succeed</title>
            </head>
            <body>
                <p style="color:red; opacity:0.7;">
                    Scan sample:
                    <p/>
                    http://127.0.0.1:5000/api/diamondring/v1.0/Scan?param={"TargetIP":"localhost","ScanProfile":{"Type":"Fast/Full","SourceiFace":"eth0","Lang":"En-Us","Extra":"DefaultPwd"}
                </p>
                <p style="color:blue; opacity:0.7;">
                    Cancel sample:
                    <p/>
                    http://127.0.0.1:5000/api/diamondring/v1.0/Cancel?param={"task_id":"140de969-12a2-46b4-95de-93700214e278"}
                </p>
                <p style="color:green; opacity:0.7;">
                    GetProgress sample:
                    <p/>
                    http://127.0.0.1:5000/api/diamondring/v1.0/GetProgress?param={"report_id":"63d61709-a187-411d-b491-3a07a1ec9d69","task_id":"140de969-12a2-46b4-95de-93700214e278"}
                </p>
                <p style="color:navy; opacity:0.7;">
                    GetResult sample:
                    <p/>
                    http://127.0.0.1:5000/api/diamondring/v1.0/GetResult?param={"report_id":"63d61709-a187-411d-b491-3a07a1ec9d69"}
                </p>
            </body>
            </html>
            '''
        
@wsapp.route(api_map["scan"]["api_path"], methods=['POST'])
def scan():
    return RequestHandler("scan")

@wsapp.route(api_map["cancel"]["api_path"], methods=['POST'])
def cancel():
    return RequestHandler("cancel")

@wsapp.route(api_map["progress"]["api_path"], methods=['GET'])
def progress():
    return RequestHandler("progress")

@wsapp.route(api_map["result"]["api_path"], methods=['GET'])
def result():
    return RequestHandler("result")
    
if __name__ == '__main__':
    wsapp.run(debug=True)
