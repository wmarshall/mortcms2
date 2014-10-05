# app.py
from flask import Flask, request, redirect, abort
from flask.ext.sqlalchemy import SQLAlchemy
from Crypto.Util.number import long_to_bytes
from Crypto.Random.random import getrandbits
from os import path, environ
from functools import wraps

app = Flask(__name__, template_folder='content/templates', static_folder='content/static')
app.config.update({
	'SQLALCHEMY_DATABASE_URI':'sqlite:///'+path.join(environ['HOME'],'mortcms.db'), #TODO: FROM ENV
	'SECRET_KEY':long_to_bytes(getrandbits(32)),
	'REQUIRE_HTTPS': False
})
db = SQLAlchemy(app)


def https_required(f):
    @wraps(f)
    def redirect_https(*args, **kwargs):
        if app.config['REQUIRE_HTTPS'] and \
                not request.url.startswith("https"):
            redirect('https://'+request.url[len("http://"):])
        return f(*args, **kwargs)
    return redirect_https

@https_required
def cms_access_required(f):
    @wraps(f)
    def fail_if_no_access(*args, **kwargs):
        if not session['cms_access']:
            abort(403)
        return f(*args, **kwargs)
    return fail_if_no_access