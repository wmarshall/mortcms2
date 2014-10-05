# cms.py
from .app import app, cms_access_required
from base64 import b64decode
from shutil import copyfile
from os import path, makedirs, walk


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
	file_path = safe_join(content_path,file)
	if request.method == 'GET':
		# Raises a NotFound which gets interpreted as a 200 for some reason
		# raise Exception
		return send_from_directory(content_path, file, mimetype='text/plain')
	elif request.method == 'POST':
		# write to file
		with open(file_path, 'w') as f:
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