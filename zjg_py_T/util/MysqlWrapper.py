import MySQLdb
import logging

class MysqlWrapper:
	conn = None
	cursor = None

	def __init__(self, dbhost, dbdatabase, dbuser, dbpwd):
		try:
			self.conn = MySQLdb.connect(host=dbhost, # host, usually localhost
	                     	user=dbuser, # username
	                      	passwd=dbpwd, #password
	                      	db=dbdatabase) # database
			self.cursor = self.conn.cursor()
		except MySQLdb.Error, e:
			print "MySQL Error: %s" % str(e)
		except:
			print "MySQLdb connect fail"

	def __del__(self):
		if self.conn:
			self.conn.close()

	def execute(self, sql, data):
		if self.conn and self.cursor:
			try:
				self.cursor.execute(sql, data)
				self.conn.commit()
			except MySQLdb.Error, e:
				print "MySQL Error: %s" % str(e)
				logging.error('MySQL Error:{0} failed'.format(str(e)))
			except:
				print "sql %s execute fail" %sql
				logging.error('sql {0} execute fail'.format(sql))

			finally:
				self.conn.rollback()

	def query(self, sql, data):
		result = ()
		if self.conn and self.cursor:
			try:
				self.cursor.execute(sql, data)
				result = result + self.cursor.fetchall()
			except MySQLdb.Error, e:
				print "MySQL Error: %s" % str(e)
				logging.error('MySQL Error:{0} failed'.format(str(e)))
			except:
				print "sql %s execute fail" %sql
				logging.error('sql {0} execute fail'.format(sql))
			finally:
				return result
		else:
			return result