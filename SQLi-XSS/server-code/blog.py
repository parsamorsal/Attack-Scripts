import MySQLdb
import re

#only letting digits pass as post id.
def only_numerics(id):
    return re.sub("[^0-9]", "", id)

def all_posts():
	try:
		db = MySQLdb.connect(user='bloguser', passwd = "6ece40f67123db28fa5d7167cd3de8c1739136f6b02d7b3f571fc4209f26a8a3", db = "Data")
		c = db.cursor()
		c.execute("""SELECT * FROM blog""")
		r = c.fetchall()

		return r
	except:
		return None


def single_post(id):
	try:
		db = MySQLdb.connect(user='bloguser', passwd = "6ece40f67123db28fa5d7167cd3de8c1739136f6b02d7b3f571fc4209f26a8a3", db = "Data")
		c = db.cursor()
        id=only_numerics(id)
		c.execute("""SELECT * FROM blog WHERE id=%s""" , (id,))
		r = c.fetchone()
		if r is None:
			return ('', '', '')

		return r
	except Exception as e:
		print(e)
		return ('', '', '')
