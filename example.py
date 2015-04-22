#!/usr/bin/env python3

from flask import Flask
from flask import render_template, redirect
from sbn import SBNMiddleware

app = Flask(__name__)
key = b">\xed\x19\xa7Q\xe5\xa1\x00ZF\xe7X4(m\xb7\x92(\x01\x90\xb1\x16\x9b\x02\xb7\xa3-\xa87\xe8\x1b[\x1a\xef\xc16\xbc\xdf\x99\xac^\xcd\x0e\xfd,\xb5\x19\x02\x9ci\xf8>\xa5\x07\x85\xa8\xc8B\xe5\xb1\x1dt\xbfV\xab|\xdd,\xa7\xcdFf\xa5H\xc6\xf1\xa9\x84\xb0\xd1\x989\x1f\xac\xa5H\xed\xa5>x{g3\x17\xf5\x04*\t\x03\xb2_\x7f&\x12\x0f%\xa2\x0e\xa3\xc3Z\x10\xb0\xea\xeb\xb7\xbam>P2\xd7\x84>\xa1\xd5!\x02\xef\xd2\xc2\xe20\x88\xf7\xd0R\x89\x18U\xcc4\xd96W\xcd\xdb\x16\xb4\x98\xf5\xf0/\xc1\xad\xa8\xe1 \xdb0\xc8\x9c\xad\x00\xcc'!\xcb\x1e\xddv\x9b\x88}\xfbR\xe1\xef\xb7L\x93\x96\x0b\xb25'p\xc78\x10\x15\x8e[$\xcd\xf2D\xd4\x05y=\xa7u\xe1)E\x94@\xd2x\x06\xa2~\x88\x17\xc2\xf4\x86\xcc\xba^\xfb>\xaf\xc7\xe3R\x02mb'\x1a\xf8\xaf\xf4\x1b\xae\xe2l\x05\xd7\xb8n\xc99i\xc5\x118\xf2\x93\x01aT\xa4\xe6"

SBN = SBNMiddleware(app.wsgi_app, key, app.logger, domainsuffix='.sbndomain.tk')
app.wsgi_app = SBN

# Replace default  url_for function with SBN.url_for
app.jinja_env.globals['nosbn_url_for'] = SBN.nosbn_url_for
app.jinja_env.globals['url_for'] = SBN.url_for
url_for = SBN.url_for

@app.route('/data')
def data():
    return 'data'

@app.route('/')
def root():
    return render_template('index.html')

@app.route('/start')
def start():
    return redirect(url_for('.hello', action=42))

@app.route('/startpath')
def start_path():
    return redirect(url_for('.hello'))

@app.route('/hello')
def hello():
    return render_template('hello.html')

@app.errorhandler(404)
def error404(error):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

