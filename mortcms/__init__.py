#!/usr/bin/env python2
from flask import Flask, flash, render_template, redirect, abort, request,\
		session, current_app, safe_join, jsonify, send_from_directory, get_flashed_messages
from flask.ext.sqlalchemy import SQLAlchemy

from uuid import uuid4, UUID
from base64 import b64decode

from functools import wraps

from shutil import copyfile

from os import path, makedirs, walk, environ

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random.random import getrandbits
from Crypto.Util.number import long_to_bytes

from .custom import GUID, ValidationError, LoginError, transaction_on

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
            # len(http://) = 7
            redirect('https://'+request.url[7:])
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


class User(db.Model):
	__tablename__ = 'user'
	id = db.Column(GUID, primary_key=True, default=uuid4)
	name = db.Column(db.Text, nullable=False)
	email = db.Column(db.Text, nullable=False, unique=True)
	salt = db.Column(db.LargeBinary)
	hash = db.Column(db.LargeBinary)
	cms_access = db.Column(db.Boolean, nullable=False, default=False)

	@db.validates('email')
	def validate_email(self, key, email_addr):
		if '@' not in email_addr:
			raise ValidationError('email')
		return email_addr

	def login(self, password):
		if self.hash is None and self.salt is None:
			# Set new password
			self.salt = long_to_bytes(getrandbits(128))
			self.hash = PBKDF2(password, self.salt)
		else:
			#actually check
			if self.hash != PBKDF2(password, self.salt):
				raise LoginError('password')
		session['user_id'] = self.id

class TempRedirect(db.Model):
	__tablename__ = 'redirect'
	id = db.Column(GUID, primary_key=True, default=uuid4)
	target = db.Column(db.Text, nullable=False)
	expires = db.Column(db.DateTime)
	data = db.Column(db.PickleType)

	def get_link(self):
		return '/tr/%s' % self.id

class RestrictedPage(db.Model):
	__tablename__ = 'restricted'
	path = db.Column(db.Text, primary_key=True)
	cms_access_required = db.Column(db.Boolean, default=False, nullable=False)

@app.route('/tr/<guid>')
def do_temp_redirect(guid):
	temp_redirect = None
	with transaction_on(db):
		try:
			temp_redirect = TempRedirect.query\
					.filter_by(id = UUID(guid))\
					.first_or_404()
			if temp_redirect.expires is not None and temp_redirect.expires < datetime.now():
				abort(410)
			flash(temp_redirect.data)
			db.session.delete(temp_redirect)
			return redirect(temp_redirect.target)
		except ValueError:
			abort(400)
	return ''

@app.before_request
def sanitize_session():
	#ensure session always returns to safe state
	if session.get('user_id') is None:
		session['user_id'] = None
		session['cms_access'] = None
		session.pop('needs_pass_reset', None)
	else:
		session['cms_access'] = User.query\
				.filter_by(id = session['user_id'])\
				.first_or_404().cms_access and not session.get('needs_pass_reset', False)

@app.before_request
def force_setpass():
	if session.get('needs_pass_reset')\
		and request.path != '/setpass' and not request.path.startswith('/static'):
		flash({'user_id':session['user_id']})
		return redirect('/setpass')

@app.route('/login', methods=['POST'])
@https_required
def login():
	with transaction_on(db):
		user = User.query\
				.filter_by(email = request.get_json()['email'])\
				.first_or_404()
		if None in [user.salt, user.hash]:
			# Can't use login without running through password reset
			abort(403)
		user.login(request.get_json()['password'])
		db.session.add(user)
	return ''

@app.route('/logout', methods=['POST'])
def logout():
	session['user_id'] = None
	session['cms_access'] = None
	return ''


@app.route('/setpass', methods=['GET','POST'])
@https_required
def set_pass():
	if request.method == 'GET':
		if not session['user_id']:
			session['user_id']= get_flashed_messages()[0]['user_id'] # Force a login so that next stage of auth completes
			session['needs_pass_reset'] = True #Flag user as needing password reset
		return render_page('setpass', user_id=session['user_id'])
	else:
		with transaction_on(db):
			user = User.query\
					.filter_by(id = session['user_id'])\
					.first_or_404()
			user.hash = None
			user.salt = None
			user.login(request.get_json()['password'])
			del session['needs_pass_reset']
			return redirect('/')

@app.route('/setemail', methods=['POST'])
@https_required
def set_email():
	with transaction_on(db):
		user = User.query\
				.filter_by(id = session['user_id'])\
				.first_or_404()
		user.email = request.get_json()['email']
		return ''

@app.route('/forgotpass', methods=['POST'])
@https_required
def forgot_pass():
	with transaction_on(db):
		user = User.query\
				.filter_by(email = request.get_json()['email'])\
				.first_or_404()
		temp_redirect = TempRedirect(target='/setpass', 
				data={'user_id':user.id})
		db.session.add(temp_redirect)
		#send_forgot_pass_email(email, temp_redirect)
	return ''

@app.route('/tree')
@cms_access_required
def content_tree():
	# Generate tree structure representing content folder
	# {"content":{"static":{...}}}
	tree = {"content":{}}
	content_path = path.join(app.root_path, 'content')
	for dirpath, dirs, files in walk(content_path):
		# app.root_path is absolute, we want tuples that look like
		# content/blah/blah
		dirpath = dirpath[len(content_path) - (len('content')):]
		# remove hidden files
		files = [f for f in files if f[0] != '.']
		# must modify dirs in place, so have to get crafty
		dirs_to_remove = [d for d in dirs if d[0] == '.']
		if dirpath == 'content':
			dirs_to_remove.append('libraries')
		for name in dirs_to_remove:
			dirs.remove(name)
		current_dir = tree
		# Move current_dir to where we need to be
		for dirname in dirpath.split('/'):
			current_dir = current_dir[dirname]
		# Set up next level
		for dirname in dirs:
			current_dir[dirname] = {}
		# Define filenames, don't know what info to send with
		for fname in files:
			current_dir[fname] = None
	# raise Exception()
	return jsonify(content = tree['content'])

@app.route('/raw/<path:file>', methods=['GET', 'POST'])
@cms_access_required
def get_raw_file(file):
	content_path = path.join(app.root_path, 'content')
	if request.method == 'GET':
		# Raises a NotFound which gets interpreted as a 200 for some reason
		# raise Exception
		return send_from_directory(content_path, file, mimetype='text/plain')
	else:
		# write to file
		with open(safe_join(content_path,file), 'w') as f:
			content = request.get_json()['content']
			if request.get_json()['binary']:
				# decode base64
				content = b64decode(content)
			else:
				content = content.encode('UTF8')
			f.write(content)
			return ''

@app.route('/preview', methods=['POST'])
@cms_access_required
def preview_template():
	return render_template_string(
			request.get_json()['new_template'], 
			**request.get_json()['context']
		)

@cms_access_required
def new_file(template, path_prefix):
	content_path = path.join(app.root_path, 'content')
	metatemplate_path = path.join(content_path, 'metatemplates')
	prefixed_path = path.join(content_path, path_prefix)
	# check that path does not exist
	final_path = path.join(prefixed_path, request.get_json()['path'])
	if path.exists(final_path):
		abort(409)
	dirname = path.dirname(final_path)

	if not path.exists(dirname):
		makedirs(dirname) # Doesn't fail if parents exist
		# But does fail if last dir exists, so wrap for safety
	copyfile(path.join(metatemplate_path,template), final_path)

@app.route('/new/page', methods=['POST'])
def new_page():
	new_file(template='page.html', path_prefix='templates/pages')
	if request.get_json()['restrict'] is not None:
		with transaction_on(db):
			restricted_page = RestrictedPage(
					path=request.get_json()['path'],
					cms_access_required=(request.get_json()['restrict'] == 'cms_access')
				)
			db.session.add(restricted_page)
	return ''

@app.route('/new/base', methods=['POST'])
def new_base():
	new_file(template='base.html', path_prefix='templates/bases')
	return ''

@app.route('/new/script', methods=['POST'])
def new_script():
	new_file(template='script.js', path_prefix='static/js')
	return ''

@app.route('/new/stylesheet', methods=['POST'])
def new_stylesheet():
	new_file(template='stylesheet.css', path_prefix='static/css')
	return ''

@app.route('/new/user', methods=['POST'])
@cms_access_required
def new_user():
	with transaction_on(db):
		newuser = User(
				name=request.get_json()['name'],
				email=request.get_json()['email'],
				cms_access=request.get_json()['cms_access']
			)
		db.session.add(newuser)
		temp_redirect = TempRedirect(target='/setpass', 
				data={'user_id':newuser.id})
		db.session.add(temp_redirect)
		# send_welcome_email(newuser, temp_redirect)
	return ''

@app.route('/favicon.ico')
def favicon():
	return redirect('/static/favicon.ico')

@app.route('/')
@app.route('/<path:page>')
def render_page(page=None, **context):
	if page is None:
		page = 'index'
	possible_names = [p + '.html' for p in [page, page+'/index']]
	restricted_pages = RestrictedPage.query\
			.filter(RestrictedPage.path.in_(possible_names))\
			.all()

	if restricted_pages:
		for restricted in restricted_pages:
			if restricted.cms_access_required and not session['cms_access']:
				# Need cms_access, don't have it
				abort(403)
			elif session['user_id'] is None:
				# Need to login
				abort(403)
	# We're good to go
	# Prepend pages now that we know the user can view the pages
	possible_names= ['pages/' + p for p in possible_names]	
	# easier than the nasty try:except block that came before it since
	# render_template tries names the iterable in the order they are provided
	content_path = path.join(app.root_path, "content")
	pages_path = path.join(content_path, "templates/pages")
	filename = page + ".html"
	template_path = path.join(pages_path, filename)
	if not path.exists(template_path):
		template_path = template_path[:-len(".html")] + "/"
		# Trim app.root path and <page>.html from initial path
	template_path = template_path[len(content_path):]
	return render_template(possible_names, template_path = template_path, **context)


@app.errorhandler(403)
def forbidden(e):
	return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found(e):
	return render_template('errors/404.html'), 404