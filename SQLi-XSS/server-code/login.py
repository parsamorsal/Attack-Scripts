import MySQLdb
import jwt


TOKEN = 'SOME_RANDOM_TOKEN::NOT_IMPORTANT_CE_SHARIF_2017_TardisDalek'


def login(user, passwd):
	try:
		db = MySQLdb.connect(user='loginuser', passwd = "705ae97d0fcd9781ba54aff2390b401aa6d6fc2ff79e430a468169ac854598ba", db = "Users")
		c = db.cursor()
		c.execute("""SELECT username, password FROM users WHERE username = %s;""", (user, ))
		r = c.fetchone()

		if r is None:
			return False

		_, p  = r

		if p == passwd:
			return True

		db.close()

		return False
	except:
		return False


def generate_cookie(user):
	str = jwt.encode({'login': True, 'user': user, 'hint': 'nothing here'}, TOKEN, algorithm='HS256')
	return str


def check_cookie(cookie):
	if cookie is None or cookie == "":
		return False

	try:
		payload = jwt.decode(cookie, TOKEN, algorithms=['HS256'])

		if payload.get('login', False) is True:
			return True
	except:
		pass
	return False
