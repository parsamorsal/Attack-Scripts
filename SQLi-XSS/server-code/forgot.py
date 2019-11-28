import MySQLdb

def check(user):
    
	try:
		db = MySQLdb.connect(user='loginuser', passwd = "705ae97d0fcd9781ba54aff2390b401aa6d6fc2ff79e430a468169ac854598ba", db = "Users")
		c = db.cursor()
        safe_query="""SELECT username FROM users WHERE username = '%s';"""
        c.execute(safe_query,(user,))
		r = c.fetchone()

		if r is None:
			return False

		return True
	except:
		return False
