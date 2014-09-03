#!/usr/bin/env python2
from mortcms import app

app.config['SECRET_KEY'] = 'insecurelocalkey'

if __name__ == '__main__':
	app.run(debug=True)