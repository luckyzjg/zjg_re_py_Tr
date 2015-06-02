from flask import jsonify
from impl.scanmgr import GetScanMgrInstance

def api_GetResult(wsapp, param_json):
    wsapp.logger.debug("api_GetResult")

    scanMgr = GetScanMgrInstance()
    result = scanMgr.GetResult(wsapp, param_json)
    return jsonify(result)
