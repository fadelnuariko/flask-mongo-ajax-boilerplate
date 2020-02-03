import uuid
from argon2 import PasswordHasher
from http.cookies import SimpleCookie

TEMPLATE = {}
DEBUG = "debug"

# initialize argon2 password hasher
ph = PasswordHasher()

def views(tpl_file, layout):
	if "header" not in TEMPLATE:
		with open('./views/layout/header.html') as html_file:
			TEMPLATE["header"] = html_file.read()
	if "footer" not in TEMPLATE:
		with open('./views/layout/footer.html') as html_file:
			TEMPLATE["footer"] = html_file.read()
	if DEBUG == "debug":
		# debugging mode
		with open('./views/{}'.format(tpl_file)) as html_file:
			if layout == True:
				response = "{}{}{}".format(TEMPLATE["header"], html_file.read(), TEMPLATE["footer"])
			else:
				response = html_file.read()
			return response
	else:
		if tpl_file in TEMPLATE:
			if layout == True:
				html = "{}{}{}".format(TEMPLATE["header"], TEMPLATE[tpl_file], TEMPLATE["footer"])
			else:
				html = TEMPLATE[tpl_file]
			return html
		else:
			with open('./views/{}'.format(tpl_file)) as html_file:
				content = html_file.read()
				TEMPLATE[tpl_file] = content
				if layout == True:
					html = "{}{}{}".format(TEMPLATE["header"], content, TEMPLATE["footer"])
				else:
					html = content
				return html

STATIC_FILE = {}

def load_file(file_name):
	ext = file_name.split(".")[-1]
	if DEBUG == "debug":
		with open('./public{}'.format(file_name), 'rb') as file:
			return file.read()
	else:
		if file_name not in STATIC_FILE:
			with open('./public{}'.format(file_name), 'rb') as file:
				STATIC_FILE[file_name] = file.read()
		return STATIC_FILE[file_name]

def post(request):
	list  = request.body.decode('utf-8').split('&')
	post = {}
	for item in list:
		p = item.split('=')
		post[p[0]]=p[1]
	return post

def proceed_guid(request):
	if "guid" not in request.cookies:
		cookies = SimpleCookie()
		cookies['guid'] = uuid.uuid4().hex
		cookies['guid']['domain'] = 'localhost'
		cookies['guid']['path'] = '/'
		cookies['guid']['max-age'] = 604300
		# cookies['guid']['secure'] = True
		return request.Response(headers={'Location': '/login'}, cookies=cookies, code=302)
	else:
		return request.Response(headers={'Location': '/login'}, code=302)

def logged(cookies, redis):
	if "guid" in cookies:
		guid = cookies["guid"]
		username = redis.get(guid) # return username
		if username is not None:
			logged_guid = redis.get(username) # return guid `guid-xxxx-xxxx-dst`
			if logged_guid is not None:
				if logged_guid.decode("utf-8") == guid:
					return True
	return False

def argon2_verify(hashed, password):
	try:
		res = ph.verify(hashed, password)
		if res == True:
			return True
	except Exception as e:
		return False

def generate_argon(string):
	return ph.hash(string)
