#!/usr/bin/env python2
from flask import flash, render_template, redirect, abort, request,\
		session, safe_join, jsonify, send_from_directory, get_flashed_messages
from os import path

from .app import app, db, https_required, cms_access_required
from .database import GUID, transaction_on, User, TempRedirect, RestrictedPage
from .util import ValidationError, LoginError

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
			# Blow up session
			session.pop('user_id', None)
			session.pop('cms_access', None)
			session.pop('needs_pass_reset', None)
			return ''

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
	return render_template('errors/403.html', template_path = '/templates/errors/403.html'), 403

@app.errorhandler(404)
def not_found(e):
	return render_template('errors/404.html', template_path = '/templates/errors/404.html'), 404