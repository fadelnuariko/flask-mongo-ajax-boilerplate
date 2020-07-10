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
mongo = client.nikah
# initialize redis connection
session = redis.Redis(host='127.0.0.1', port=6379, db=0)

app = Flask(__name__)

# for test
@app.route("/post", methods=["POST"])
def post():
	nama = request.form["nama"]
	ucapan = request.form["ucapan"]

	date = datetime.now()
	today = f"{date.year}-{date.month}-{date.day}"

	data = {
		"nama" : nama,
		"ucapan" : ucapan,
		"date" : today
	}

	mongo["buku"].insert_one(data)
	return Response(dumps({"status" : "ok"}), mimetype="application/json")

@app.route("/get")
def winransom_attack_list():
	data = mongo["buku"].find()
	return Response(dumps(data), mimetype="application/json")

@app.route("/")
def index():
	return "hore"
