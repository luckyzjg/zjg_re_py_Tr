from flask import jsonify
from impl.scanmgr import GetScanMgrInstance

def api_Scan(wsapp, param_json):
    wsapp.logger.debug("api_Scan")
    scanMgr = GetScanMgrInstance()
    result = scanMgr.Scan(wsapp, param_json)
    return jsonify(result)
