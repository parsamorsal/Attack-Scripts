from flask import Flask, request, make_response, redirect, send_from_directory

from Crypto.Hash import SHA256

import login as login_handler
import forgot as forgot_handler
import blog as blog_handler
import re


def check_login():
	try:
		t = request.cookies.get('token')
		return login_handler.check_cookie(t)
	except:
		return False


def escape_mysql(s):
	if s is None:
		return None

	rm = ['INSERT', 'AND', 'OR', 'SELECT', 'UNION', 'WHERE', 'LIKE', 'TABLE', 'LIMIT', 'OFFSET', 'JOIN', 'FROM', 'INTO', 'DELETE']
	err = ['\'', '"', '`', ';']
	for x in err:
		if x in s:
			return None
	# oh this is so smart.
	for x in rm:
		print(x, s)
		s = re.sub(x, '', s, flags=re.IGNORECASE)

	return s


app = Flask('', static_url_path='/static', static_folder='static')


@app.route("/logout")
def logout():
	resp = make_response(redirect("/"))
	resp.set_cookie('token', '')
	return resp


@app.route("/")
def root():
	return app.send_static_file('index.html')


@app.route("/forgot.html")
def forgot():
	return app.send_static_file('forgot.html')


@app.route('/login', methods=['POST'])
def login():
	u = request.form.get('username')
	p = request.form.get('password')
	if u is None or p is None:
		return 'Wrong user/pass'
	if not login_handler.login(u, p):
		return 'Wrong user/pass'
	resp = make_response(redirect('/blog'))
	resp.set_cookie('token', login_handler.generate_cookie(u))
	return resp


@app.route('/forgot', methods=['POST'])
def check():
	u = request.form.get('username')
	if u is None:
		return 'User does not exists'
	if not forgot_handler.check(u):
		return 'User does not exists'
	return "Okay"


@app.route('/protected/<path:filename>', methods=['POST'])
def protected(filename):
	if not check_login():
		return "NO!!!!!!!!!!"
	flag = request.form.get('flag')
	if flag is None:
		return 'No'
	flag = flag.strip()
	hash = SHA256.new()
	hash.update(flag.encode('utf-8'))

	if hash.hexdigest() != '74d8418904bde8361e4542da78e8b5297bf3f9f9e91ec83349a46080a275e65a':
		return 'No'
	return send_from_directory('protected', filename)


@app.route('/blog')
def blog():
	if not check_login():
		return "NO!!!!!!!!!!"

	header = """
<html>
<head>
<title>Blog posts</title>
<style>
img {
	width: 300px;
}
</style>
</head>
<body>
<h2>Download Source Code</h2>
<form method="post" action="/protected/source.tar.gz">
	flag? <input type="text" name="flag" />
	<input type="submit" value="send!" />
</form>
<h1>Blog Posts</h1>
"""
	footer = """
</body>
</html>
"""
	posts = blog_handler.all_posts()
	if posts is None:
		posts = []
	s = header
	for (id, title, body) in posts:
		s += "<h3><a href=\"/post?id=%s\">%s</a></h3>" % (id, title)
		s += body
		s += "<br /><br />"
	s += footer
	return s


@app.route('/post')
def post():
	if not check_login():
		return "NO!!!!!!!!!!"

	header = """
<html>
<head>
<title>Blog Post</title>
<style>
img {
	width: 300px;
}
</style>
</head>
<body>
<h1>Blog Posts</h1>
"""
	footer = """
</body>
</html>
"""
	id = escape_mysql(request.args.get("id"))
	print('id', id)
	if id is None:
		return "Error :("
	result = blog_handler.single_post(id)
	s = header
	(id, title, body) = result
	s += "<h3><a href=\"/post?id=%s\">%s</a></h3>" % (id, title)
	s += body
	s += "<br /><br />"
	s += footer
	return s

#@app.route('/static/<path:path>')
#def static(path):
#	return send_from_directory('static', path)


app.run(host='0.0.0.0', port=8008)
