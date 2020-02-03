from flask import Flask, escape, request, redirect
from flask import make_response, Response
from flask import json
from loader import views, load_file
from pymongo import MongoClient
from bson.json_util import dumps
from datetime import datetime, timedelta

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

import redis
import uuid
import time
import bcrypt

# initialize mongo connection
client = MongoClient('mongodb://127.0.0.1:27017')
mongo = client.flask_mongo_boilerplate
# initialize redis connection
session = redis.Redis(host='127.0.0.1', port=6379, db=0)

app = Flask(__name__)

@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == "GET":
		if "guid" in request.cookies:
			return Response(views("login.html", False), mimetype='text/html')
		else:
			response = make_response(redirect('/login'))
			response.set_cookie('guid', value=uuid.uuid4().hex, max_age=604300, path="/", httponly=True)
			return response
	else:
		if "username" in request.form and "password" in request.form:
			username = request.form["username"]
			password = request.form["password"]
			get_user = mongo["users"].find_one({"username": username})
			if get_user is not None:
				# account is exist, do password verify
				if bcrypt.checkpw(password.encode(), get_user["password"]):
					guid = request.cookies["guid"]
					user_gid = "gid-{}".format(guid) # user get user gid
					user_ss = "ss-{}".format(guid) # user single session
					session.set(username, guid, 604800)
					session.set(guid, username, 604800)
					session.set(user_gid, get_user["guid"], 604800)
					session.set(user_ss, "1")
					return redirect("/", code=302)
		return redirect("/login", code=302)

@app.route('/logout')
def logout():
	if "guid" in request.cookies:
		guid = request.cookies["guid"]
		user_gid = "gid-{}".format(guid)
		user_ss = "ss-{}".format(guid) # user single session
		session.delete(user_gid)
		session.delete(guid)
		session.delete(user_ss)
	return redirect("/login", code=302)

def get_uuid_from_cookie(guid):
	res = session.get("gid-{}".format(guid))
	if res is not None:
		return res.decode("utf-8")
	return ""

MIME_TYPE = {"gif": "image/gif", "svg": "image/svg+xml", "jpg": "image/jpg", "jpeg": "image/jpeg", "js": "text/javascript", "css": "text/css", "png": "image/png", "woff": "font/woff", "woff2": "font/woff2", "map": "application/json"}
@app.route('/assets/<path:path>')
def assets(path):
	ext = request.path.split("/")[-1].split(".")[-1]
	return Response(load_file(request.path), mimetype=MIME_TYPE[ext])

def get_user_config(guid):
	get_user = mongo["users"].find_one({"uuid": guid}, {"feature_status": 1})
	if get_user:
		get_user = json.loads(dumps(get_user))
		if "feature_status" in get_user:
			return get_user
	data = mongo["site_settings"].find_one({"type": "default-user-config"}, {"feature_status": 1})
	return data

@app.route("/api/config/user")
def api_config_user():
	guid = get_uuid_from_cookie(request.cookies["guid"])
	if guid == "":
		return redirect("/login", code=302)
	config = get_user_config(guid)
	return Response(dumps(config), mimetype="application/json")

# for test
@app.route("/create-user")
def create_user():
	password = b"tester"
	hashed = bcrypt.hashpw(password, bcrypt.gensalt())

	data = {
		"_id": "static_id_for_test",
		"guid": str(uuid.uuid4()),
		"username": "tester",
		"password": hashed,
		"created_at": int(time.time()),
	}

	mongo["users"].insert_one(data)
	return "ok"

@app.route("/")
def index():
	return views("content/index.html", True)
