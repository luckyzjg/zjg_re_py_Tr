class DRError:
	def __init__(self):
		self.dict = {
			'Success':'0',
			'UserCancel':'90000001',
			'InvalidParm':'90000002',
			'InvalidSessionId':'90000003',
			'ScriptError':'90000004',
			'DatabaseError':'90000005',
			'NmapError':'90001000',
			'DevScanFailed':'90001001',
			'PwdScanFailed':'90001002',
			'OpenvasError':'90002000',
			'VulScanFailed':'90002001',
			'VulLogSaveFailed':'90002002',
			'ParserError':'90003000',
			'DevLogParseFailed':'90003001',
			'VulLogParseFailed':'90003002',
			'PwdParseFailed':'90003003',
		}

	def GetErrCode(self, err_str):
		print self.dict[err_str]
		return self.dict[err_str]
