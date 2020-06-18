# /server.py

from functools import wraps
import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask, request
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

from jinja2 import Markup
import mysql.connector as sql

# infoDict['js']= Markup(js)


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.debug = True
app.secret_key = "super secret key"

#  Here i am making a connection with mysql database hosted by the xampp server!
db = sql.connect(
    host="localhost",
    user="root",
    password="",
    database="project_wang_reda"
)
#  Then i am making a cursor to execute sql commands in the following below functions and decorators
cursor = db.cursor()

@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response


oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    redirect="GG",
    client_id='EiQUVvi2sUFVHxmUfFVmTsq2CJj6I9VR',
    client_secret='eFKgAM50K89r6BiN3cvzEm3-UAh5WDPnbXj3AFTqHQ_s1idiPKzLzHaQD2E1XRMY',
    api_base_url='https://dev-jb-2phci.us.auth0.com',
    access_token_url='https://dev-jb-2phci.us.auth0.com/oauth/token',
    authorize_url='https://dev-jb-2phci.us.auth0.com/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


@app.route("/")
def homepage():
    return render_template('homepage.html')


# Here we're using the /callback route.
@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/dashboard')


@app.route('/login')
def login():
    return auth0.authorize_redirect(redirect_uri='http://localhost:5000/callback')


# /server.py

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'profile' not in session:
            # Redirect to Login page here
            return redirect('/')
        return f(*args, **kwargs)

    return decorated


# /server.py

@app.route('/dashboard')
@requires_auth
def dashboard():
    return (render_template('/index.html',
                            userinfo=session['profile'],
                            userinfo_pretty=json.dumps(session['jwt_payload'], indent=4)))


# /server.py

@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('/', _external=True), 'client_id': 'EiQUVvi2sUFVHxmUfFVmTsq2CJj6I9VR'}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


@app.route('/dashboard/demography')
@requires_auth
def demography():
    return (render_template('/charts.html',
                            userinfo=session['profile'],
                            userinfo_pretty=json.dumps(session['jwt_payload'], indent=4)))


@app.route('/dashboard/datacompendium')
@requires_auth
def datacompendium():
    return (render_template('/tables.html',
                            userinfo=session['profile'],
                            userinfo_pretty=json.dumps(session['jwt_payload'], indent=4)))


@app.route('/dashboard/gallery')
@requires_auth
def gallery():
    return (render_template('/gallery.html',
                            userinfo=session['profile'],
                            userinfo_pretty=json.dumps(session['jwt_payload'], indent=4)))


@app.route('/api/report_suspect/', methods=['GET'])
def report_suspect_api():
    # data is received in http get method
    suspected_name = request.args.get('suspected_name')
    symptoms = request.args.get('symptoms')
    address = request.args.get('address')
    age = request.args.get('age')
    reported_date = request.args.get('reported_date')
    # now check if all the data are available and only then execute mysql commands.
    if suspected_name is None or symptoms is None:
        return "{'status':'0'}"
    else:
        sql_query = "INSERT INTO suspect_reports (name,symptoms,address,age,reported_date) VALUES (%s,%s,%s,%s,%s)"
        values = (suspected_name, symptoms, address, age, reported_date)
        cursor.execute(sql_query, values)
        db.commit()
        return "{'status':" + "'" + str(cursor.rowcount) + "'}"


if __name__ == "__main__":
    app.run("localhost")
