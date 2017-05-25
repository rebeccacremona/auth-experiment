from os import environ
import requests
from functools import wraps
from urlparse import urlparse, urljoin
from datetime import datetime, timedelta

from flask import Flask, request, redirect, session, abort, url_for


app = Flask(__name__)
app.config['GITHUB_CLIENT_ID'] = environ.get('GITHUB_CLIENT_ID')
app.config['GITHUB_CLIENT_SECRET'] = environ.get('GITHUB_CLIENT_SECRET')
app.config['GITHUB_ORG_NAME'] = environ.get('GITHUB_ORG_NAME')
app.config['SECRET_KEY'] = environ.get('FLASK_SECRET_KEY')
app.config['SESSION_COOKIE_SECURE'] = environ.get('SESSION_COOKIE_SECURE', False)
app.config['LOGIN_EXPIRY_MINUTES'] = environ.get('LOGIN_EXPIRY', 30)

AUTHORIZE_URL = 'https://github.com/login/oauth/authorize'
ACCESS_TOKEN_URL = 'https://github.com/login/oauth/access_token'
ORGS_URL = 'https://api.github.com/user/orgs'
REVOKE_TOKEN_URL = 'https://api.github.com/applications/{}/tokens/'.format(app.config['GITHUB_CLIENT_ID'])

###
### UTILS ###
###

def login_required(func):
    @wraps(func)
    def handle_login(*args, **kwargs):
        logged_in = session.get('logged_in')
        valid_until = session.get('valid_until')
        if valid_until:
            valid = datetime.strptime(valid_until, '%Y-%m-%d %H:%M:%S') > datetime.utcnow()
        else:
            valid = False
        if logged_in and logged_in == "yes" and valid:
            return func(*args, **kwargs)
        else:
            print "Redirecting to GitHub"
            session['next'] = request.url
            return redirect('{}?scope=user&client_id={}'.format(AUTHORIZE_URL, app.config['GITHUB_CLIENT_ID']))
    return handle_login

def is_safe_url(target):
    '''
        Ensure a url is safe to redirect to, from WTForms
        http://flask.pocoo.org/snippets/63/from WTForms
    '''
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

###
### ROUTES
###

@app.route('/')
@login_required
def hello_world():
    return "Authenticated!"

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return "Logged out!"

@app.route('/auth/github/callback')
def authorized():
    print "Requesting Access Token"
    r = requests.post(ACCESS_TOKEN_URL, headers={'accept': 'application/json'},
                                        data={'client_id': app.config['GITHUB_CLIENT_ID'],
                                              'client_secret': app.config['GITHUB_CLIENT_SECRET'],
                                              'code': request.args.get('code')})
    data = r.json()
    if r.status_code == 200:
        access_token = data.get('access_token')
        scope = data.get('scope')
        print "Received Access Token"
    else:
        print("Failed attempt. Gitub says {}".format(data['message']))
        abort(500)

    if scope == 'user':
        print 'Requesting User Organization Info'
        r = requests.get(ORGS_URL, headers={'accept': 'application/json',
                                            'authorization': 'token {}'.format(access_token)})

        print 'Revoking Github Access Token'
        # https://developer.github.com/v3/oauth_authorizations/#revoke-an-authorization-for-an-application
        d = requests.delete(REVOKE_TOKEN_URL + access_token, auth=(app.config['GITHUB_CLIENT_ID'], app.config['GITHUB_CLIENT_SECRET']))
        print '(Request returned {})'.format(d.status_code)

        data = r.json()
        if r.status_code == 200:
            if data and any(org['login'] == app.config['GITHUB_ORG_NAME'] for org in data):
                next = session.get('next')
                session.clear()
                valid_until = (datetime.utcnow() + timedelta(seconds=60*30)).strftime('%Y-%m-%d %H:%M:%S')
                session['valid_until'] = valid_until
                session['logged_in'] = "yes"
                if next and is_safe_url(next):
                    return redirect(next)
                return redirect(url_for('hello_world'))
            else:
                print("Not a member of LIL.")
                abort(403)
        else:
            print("Failed attempt. Gitub says {}".format(data['message']))
            abort(500)
    else:
        print("Insufficient scope authorized in Github")
        abort(403)

if __name__ == '__main__':
    port = int(environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
