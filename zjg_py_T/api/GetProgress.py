from flask import jsonify
from impl.scanmgr import GetScanMgrInstance

def api_GetProgress(wsapp, param_json):
    wsapp.logger.debug("api_GetProgress")
    scanMgr = GetScanMgrInstance()
    result = scanMgr.GetProgress(wsapp, param_json)
    return jsonify(result)
