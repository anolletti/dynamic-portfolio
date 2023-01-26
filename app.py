from forms import CourseForm
import smtplib
import requests
import os
import datetime
from dotenv import load_dotenv
import uuid
from flask import Flask, render_template, session, request, redirect, url_for
from flask_session import Session  # https://pythonhosted.org/Flask-Session
import msal
import app_config

load_dotenv()

app = Flask(__name__)
app.config.from_object(app_config)
Session(app)

app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
MY_PASSWORD = os.environ['MY_PASSWORD']
MY_EMAIL = os.environ['MY_EMAIL']
VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'




@app.route('/', methods=('GET', 'POST'))
def index():
    today = datetime.date.today()
    year = today.year
    form = CourseForm()

    if request.method == 'POST':
        secret_response = request.form['g-recaptcha-response']

        verify_response = requests.post(
            url=f'{VERIFY_URL}?secret={RECAPTCHA_PRIVATE_KEY}&response={secret_response}').json()

        if not verify_response['success']:
            return render_template('invalid.html', form=form)

        sender_name = form.name.data
        sender_email = form.email.data
        message = form.message.data

        with smtplib.SMTP('smtp.gmail.com', 587) as connection:
            connection.starttls()
            connection.login(MY_EMAIL, MY_PASSWORD)
            connection.sendmail(
                from_addr=MY_EMAIL,
                to_addrs=[MY_EMAIL, sender_email],
                msg=f"Subject:{sender_name}'s Inquiry\n\nHello {sender_name}, \n\nBelow is the inquiry you submitted "
                    f"on my site:\n\n*****************************\n\n{message}\n\n*****************************\n\nI "
                    f"will get back to you shortly! \n\nSincerely,\n\nAnthony "
            )

        return render_template("success.html", sender_name=sender_name, sender_email=sender_email, message=message)

    return render_template('index.html', form=form, year=year)


@app.route('/success')
def success():
    today = datetime.date.today()
    year = today.year
    return render_template('success.html')

@app.route('/login')
def login():
    today = datetime.date.today()
    year = today.year
    session["flow"] = _build_auth_code_flow(scopes=app_config.SCOPE)
    return render_template("login.html", auth_url=session["flow"]["auth_uri"], version=msal.__version__)


from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

@app.route("/access")
def access():
    today = datetime.date.today()
    year = today.year
    if not session.get("user"):
        return redirect(url_for("login"))
    return render_template('access.html', user=session["user"], version=msal.__version__)

@app.route(app_config.REDIRECT_PATH)  # Its absolute URL must match your app's redirect_uri set in AAD
def authorized():
    try:
        cache = _load_cache()
        result = _build_msal_app(cache=cache).acquire_token_by_auth_code_flow(
            session.get("flow", {}), request.args)
        if "error" in result:
            return render_template("auth_error.html", result=result)
        session["user"] = result.get("id_token_claims")
        _save_cache(cache)
    except ValueError:  # Usually caused by CSRF
        pass  # Simply ignore them
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()  # Wipe out user and its token cache from session
    return redirect(  # Also logout from your tenant's web session
        app_config.AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("index", _external=True))

@app.route("/graphcall")
def graphcall():
    token = _get_token_from_cache(app_config.SCOPE)
    if not token:
        return redirect(url_for("login"))
    graph_data = requests.get(  # Use token to call downstream service
        app_config.ENDPOINT,
        headers={'Authorization': 'Bearer ' + token['access_token']},
        ).json()
    return render_template('display.html', result=graph_data)


def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache

def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()

def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        app_config.CLIENT_ID, authority=authority or app_config.AUTHORITY,
        client_credential=app_config.CLIENT_SECRET, token_cache=cache)

def _build_auth_code_flow(authority=None, scopes=None):
    return _build_msal_app(authority=authority).initiate_auth_code_flow(
        scopes or [],
        redirect_uri=url_for("authorized", _external=True))

def _get_token_from_cache(scope=None):
    cache = _load_cache()  # This web app maintains one cache per session
    cca = _build_msal_app(cache=cache)
    accounts = cca.get_accounts()
    if accounts:  # So all account(s) belong to the current signed-in user
        result = cca.acquire_token_silent(scope, account=accounts[0])
        _save_cache(cache)
        return result

app.jinja_env.globals.update(_build_auth_code_flow=_build_auth_code_flow)  # Used in template


if __name__ == '__main__':
    app.run(debug=True)

