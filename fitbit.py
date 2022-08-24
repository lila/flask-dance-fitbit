""" an example application that integrates with flask-dance and fitbit OAuth.

A simple but complete canonical application that uses the flask-dance
auth library to authenticate users with Fitbit OAuth.

    Typical usage:

    1. set up environment in .env (see .env-example for template)
    2. setup the python environment using vscode/devcontainers or
        venv
    3. run % flask run to deploy application to localhost

Once the application is running, the following paths are available:

    /               - root path, just shows you if you are logged in
    /login          - to login using flask-login
    /logout         - to logout from flask-login
    /fitbitlogin    - initiates the fitbit authentication process
                        redirects to / when done
    /fitbitlogout   - forced logout from fitbit
    /fitbittest     - print users fitbit profile information to test
"""

import base64
import os
from time import time
import logging
import sys

from werkzeug.middleware.proxy_fix import ProxyFix

import flask_login
from flask import Flask, redirect, request, url_for
from flask_dance.contrib.fitbit import fitbit, make_fitbit_blueprint


app = Flask(__name__)

# Some logging setup
stream_handler = logging.StreamHandler()
formatter = logging.Formatter(
    "[%(asctime)s] [%(process)d] [%(levelname)s] [%(name)s]: "
    "%(pathname)s:%(lineno)d - "
    "%(message)s"
)
stream_handler.setFormatter(formatter)
app.logger.addHandler(stream_handler)
app.logger.info("app started")
logging.basicConfig(level=logging.DEBUG)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=5, x_host=5, x_proto=5, x_prefix=5)
app.logger.info("applied proxy fix")
app.logger.debug(f"wsgi.url_scheme = {os.environ['wsgi.url_scheme']}")

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit")
app.config["FITBIT_OAUTH_CLIENT_ID"] = os.environ.get("FITBIT_OAUTH_CLIENT_ID")
app.config["FITBIT_OAUTH_CLIENT_SECRET"] = os.environ.get(
    "FITBIT_OAUTH_CLIENT_SECRET")
fitbit_bp = make_fitbit_blueprint(scope=["activity", "profile"])
app.register_blueprint(fitbit_bp, url_prefix="/services")

login_manager = flask_login.LoginManager()
login_manager.init_app(app)


users = {"foo@bar.tld": {"password": "secret"}}


class User(flask_login.UserMixin):
    pass


@login_manager.user_loader
def user_loader(email):

    app.logger.debug(f"user_loader ({email})")

    if email not in users:
        return

    user = User()
    user.id = email
    return user


@login_manager.request_loader
def request_loader(req):

    app.logger.debug(f"request_loader")

    email = req.form.get("email")
    if email not in users:
        return

    user = User()
    user.id = email
    return user


@login_manager.unauthorized_handler
def unauthorized_handler():
    return "Unauthorized", 401


@app.route("/")
@flask_login.login_required
def index():
    """prints the current status of login

    prints the state of flask-login session along with the
    state of the fitbit oauth.
    """

    app.logger.debug("index")

    return (
        "Logged in as: "
        + flask_login.current_user.id
        + ": fitbit: "
        + str(fitbit.authorized)
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    """presents login screen for user, and logs in user using flask-login

    on an GET operation, returns simple html form that allows the user to
    log in.  On POST, extracts the posted variables email and password and
    uses flask-login to authenticate user.

    Returns:
        if successful, redirects to /
        if not successful, shows "bad login"
    """

    app.logger.debug("/login")

    if request.method == "GET":
        return """
               <form action='login' method='POST'>
                <input type='text' name='email' id='email' placeholder='email'/>
                <input type='password' name='password' id='password' placeholder='password'/>
                <input type='submit' name='submit'/>
               </form>
               """

    email = request.form["email"]

    app.logger.info(f"/login with {email} attempted")

    if email in users and request.form["password"] == users[email]["password"]:
        user = User()
        user.id = email
        flask_login.login_user(user)
        return redirect(url_for("index"))

    return "Bad login"


@app.route("/logout")
@flask_login.login_required
def logout():
    """logout from flask-login

    uses flask-login library to logout user and clear session cookies.

    Return:
        the string "Logged out"
    """

    app.logger.debug("/logout")

    flask_login.logout_user()
    return "Logged out"


@app.route("/fitbitlogin")
def fitbitlogin():
    """uses flask-dance to initiated fitbit Oauth login

    seperate from the user login using flask-login, this route will
    initiated an OAuth2 session login from fitbit.

    Return:
        if successfull, will return to / route
    """
    if not fitbit.authorized:
        return redirect(url_for("fitbit.login"))

    redirect("/fitbittest")


@app.route("/fitbittest")
def testfitbitlogin():
    """tests the fitbit/flask-dance state by accessing users fitbit profile

    Assumes that the user logged in with fitbit. if not, then an error
    message is printed.
    """
    if not fitbit.authorized:
        return "not logged in... error"

    print("access token: " + fitbit_bp.token["access_token"])
    print("refresh_token: " + fitbit_bp.token["refresh_token"])
    print("expiration time " + str(fitbit_bp.token["expires_at"]))
    print("             in " + str(fitbit_bp.token["expires_in"]))

    resp = fitbit.get(
        "/1/user/-/profile.json",
        headers={"Authorization": "Bearer " + fitbit_bp.token["access_token"]},
    )
    return resp.content


@app.route("/fitbitlogout")
def fitbitlogout():
    """logs the user out from their fitbit account through OAuth2

    deletes all the state for the fitbit user, but does not affect
    the flask-login state.  State that is deleted includes the
    serverside token, the session cookie, and to ensure security,
    will revoke the token from the fitbit api.
    """
    s = fitbit_bp.client_id + ":" + fitbit_bp.client_secret
    basic = base64.b64encode(s.encode("ascii")).decode("ascii")
    if fitbit.authorized:
        token = fitbit_bp.token["access_token"]
        del fitbit_bp.token
        resp = fitbit.post(
            "/oauth2/revoke",
            params={"token": token},
            headers={
                "Authorization": "Basic " + basic,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        return resp.content
    return "not logged in"


@app.route("/fitbitexpiretoken")
def fitbitexpire():
    """expires the fitbit token and forces a token refresh"""

    if fitbit.authorized:
        time_past = time() - 10
        fitbit_bp.token["expires_at"] = time_past
        print("access token: " + fitbit_bp.token["access_token"])
        print("refresh_token: " + fitbit_bp.token["refresh_token"])
        print("expiration time " + str(fitbit_bp.token["expires_at"]))
        print("             in " + str(fitbit_bp.token["expires_in"]))

        # this will fail due to expired token or be refreshed automatically
        try:
            resp = fitbit.get(
                "/1/user/-/profile.json",
                headers={"Authorization": "Bearer " +
                         fitbit_bp.token["access_token"]},
            )
            print(resp)
            print("access token: " + fitbit_bp.token["access_token"])
            print("refresh_token: " + fitbit_bp.token["refresh_token"])
            print("expiration time " + str(fitbit_bp.token["expires_at"]))
            print("             in " + str(fitbit_bp.token["expires_in"]))

        except Exception:
            print("exception")

        return "done"


if __name__ == "__main__":
    server_port = os.environ.get("PORT", "8080")
    app.run(debug=True, port=server_port, host="0.0.0.0")
