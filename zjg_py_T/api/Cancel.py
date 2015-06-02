from flask import jsonify
from impl.scanmgr import GetScanMgrInstance

def api_Cancel(wsapp, param_json):
    wsapp.logger.debug("api_Cancel")

    scanMgr = GetScanMgrInstance()
    result = scanMgr.Cancel(wsapp, param_json)
    return jsonify(result)
