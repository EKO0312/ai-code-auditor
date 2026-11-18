# Deliberately vulnerable sample for testing the auditor. Do not deploy.
# All credentials below are fake demo values, not real secrets.
import os
import random
import pickle
import hashlib
import subprocess
import sqlite3

import yaml
import requests
import flask
import flask_secure_auth_helperz

API_KEY = "demo-value-not-a-real-credential-0001"
DB_PASSWORD = "demo-password-not-real-0002"

app = flask.Flask(__name__)


@app.route("/user/<uid>")
def user(uid):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    return str(cur.fetchall())


@app.route("/run/<cmd>")
def run(cmd):
    subprocess.run(cmd, shell=True)
    os.system("echo " + cmd)
    return eval(cmd)


def load(blob):
    return pickle.loads(blob), yaml.load(blob)


def reset_token():
    reset_token = "".join(random.choice("abcdef0123456789") for _ in range(12))
    return reset_token, hashlib.md5(b"pw").hexdigest()


def fetch():
    return requests.get("https://example.com", verify=False)


if __name__ == "__main__":
    app.run(debug=True)
