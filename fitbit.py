# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""an example application that integrates with flask-dance, fitbit OAuth,
and google cloud firestore.

A simple but complete canonical application that uses flask_login to
restrict access to the site, uses fitbit oauth to retrieve consent to
access user's fitbit data, and stores the auth tokens in a backend cloud
firestore instance.

As users login and consent, the tokens will be created; when users signout
of the fitbit consent, those tokens will be deleted (but not revoked).

    User Flow:

    1. user goes to the site url "/"  and is presented with login and
       fitbit auth status or "unauthorized" if not logged in.

    2. user goes to "/login" to authenticate to the site using flask_login,
       specifies user1/secret or user2/secret to login and is redirected
       back to index "/" which should now say

        "logged in as user1 Fitbit: false"

    3. user goes to "/fitbitlogin" to associate fitbit login with user login.
       user will be presented with standard oauth process and then is
       redirected back to index "/" this time with a message:

        "logged in as user1 Fitbit: true"

    4. At this point, the backend firecloud storage will have a document
       called "user1" with the auth tokens to access fitbit.  to test,
       go to "/fitbittest" and this should return the raw profile information
       in json format.

    5. test batch action by going to "/allfitbitusers" which will cycle through
       all the user fitbit tokens and retrieve profile information from each.
       the page will just show an python list of users with associated profile
       info.

    6. to disassociated the fitbit account with the user account, go to
       "/fitbitlogout".  this will delete the backend token in firecloud and
       redirect back to index "/" which will say that fibit is false.

    7. to leave the associate in place, but logout of the website, go to
       "/logout" which will log the user out.  if you log in again, the
       fitbit association will still be there.

    to setup:

    1. set up environment in .env (see .env-example for template)
    2. get a GCP service account json file and store as service-account.json
    3. setup the python environment using vscode/devcontainers or
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
    /allfitbitusers - loop through all fitbit tokens and retrieve profile
                      information for each (like a batch operation)
    /fitbitexpiretoken - force the token to expire and see if it gets
                      renewed.  will update the backend as well.
"""
from time import time
import os
import logging
from werkzeug.middleware.proxy_fix import ProxyFix
import flask_login
from flask import Flask, redirect, request, url_for
from flask_dance.contrib.fitbit import fitbit, make_fitbit_blueprint

from storage import FirestoreStorage

app = Flask(__name__)

# Some logging setup
logging.basicConfig(level=logging.DEBUG)

# fix for running behind a proxy (eg. cloud run)
app.wsgi_app = ProxyFix(app.wsgi_app)

# application settings (typically loaded from the .env file)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit")
app.config["FITBIT_OAUTH_CLIENT_ID"] = os.environ.get("FITBIT_OAUTH_CLIENT_ID")
app.config["FITBIT_OAUTH_CLIENT_SECRET"] = os.environ.get(
    "FITBIT_OAUTH_CLIENT_SECRET"
)
FITBIT_SCOPES = [
    "activity",
    "heartrate",
    "location",
    "nutrition",
    "profile",
    "settings",
    "sleep",
    "social",
    "weight",
]

# configure the oauth backend (in this case using cloud firestore).
# by default, fitbit_bp uses a session object to store tokens, see
# https://flask-dance.readthedocs.io/en/latest/api.html#storages
firestorage = FirestoreStorage("tokens")
fitbit_bp = make_fitbit_blueprint(scope=FITBIT_SCOPES, storage=firestorage)
app.register_blueprint(fitbit_bp, url_prefix="/services")

# setup flask_login with a local simple login manager
login_manager = flask_login.LoginManager()
login_manager.init_app(app)

# users/passwords are defined here for the local login manager
users = {"user1": {"password": "secret"}, "user2": {"password": "secret"}}


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

    app.logger.debug("request_loader")

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
    """prints the current status of flask_login and fitbit login

    since flask_dance is configured to use firestore as backend token
    storage, the fitbit login is retrieved for the current logged in
    user.
    """

    app.logger.debug("index")

    firestorage.user = flask_login.current_user.id

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
    firestorage.user = None

    return "Logged out"


@app.route("/fitbitlogin")
def fitbitlogin():
    """uses flask-dance to initiated fitbit Oauth login

    seperate from the user login using flask-login, this route will
    initiated an OAuth2 session login from fitbit.  retrieved tokens
    are stored in firecloud.

    Return:
        if successfull, will return to / route which should now show
        fitbit login as true
    """

    # for testing, its useful to be able to force a user value other
    # than the current user id.  if you add "&user=bobsmith" to the url,
    # then the backend firestore document will be named bobsmith.
    username = request.args.get("user")

    # for testing, its useful to be able to force a reauth to fitbit.
    # to do so, add "&force=1" to the url
    force = request.args.get("force")

    if username is None:
        username = flask_login.current_user.id

    fitbit_bp.storage.user = username
    app.logger.debug(username)

    if not fitbit.authorized or force:
        return redirect(url_for("fitbit.login"))

    return redirect("/fitbittest")


@app.route("/fitbittest")
def testfitbitlogin():
    """tests the fitbit/flask-dance state by accessing users fitbit profile

    Assumes that the user logged in with fitbit. if not, then an error
    message is printed.
    """
    result = []

    # for testing, its useful to be able to force a user value other
    # than the current user id.  if you add "&user=bobsmith" to the url,
    # then the backend firestore document retrieved will be bobsmith.
    username = request.args.get("user")
    if username is None:
        username = flask_login.current_user.id

    if username is None:
        return "no username available"

    fitbit_bp.storage.user = username
    app.logger.debug(username)

    token = fitbit_bp.token
    print("access token: " + token["access_token"])
    print("refresh_token: " + token["refresh_token"])
    print("expiration time " + str(token["expires_at"]))
    print("             in " + str(token["expires_in"]))

    resp = fitbit.get("/1/user/-/profile.json")
    app.logger.debug(resp)
    result.append(resp.content)

    return str(result)


@app.route("/allfitbitusers")
def testfitbitlogin1():
    """tests batch operation.  loads data for all fitbit users for which
    it has the tokens available.
    """

    result = []
    for x in firestorage.all_users():

        app.logger.debug("user = " + x)

        firestorage.user = x
        if fitbit_bp.session.token:
            del fitbit_bp.session.token

        token = fitbit_bp.token
        print("access token: " + token["access_token"])
        print("refresh_token: " + token["refresh_token"])
        print("expiration time " + str(token["expires_at"]))
        print("             in " + str(token["expires_in"]))

        resp = fitbit.get("/1/user/-/profile.json")
        j = resp.json()
        app.logger.debug(f"{x}: {j['user']['fullName']}")
        result.append(
            f"{x}: {j['user']['fullName']} ({j['user']['gender']}/{j['user']['age']})"
        )

    firestorage.user = None

    return result


@app.route("/fitbitlogout")
def fitbitlogout():
    """logs the user out from their fitbit account through OAuth2

    deletes all the state for the fitbit user, but does not affect
    the flask-login state.

    Note:
        does not revoke the token.  that might be a good idea to do.
    """
    if fitbit.authorized:
        del fitbit_bp.token
        return "removed fitbit tokens"

    # s = fitbit_bp.client_id + ":" + fitbit_bp.client_secret
    # basic = base64.b64encode(s.encode("ascii")).decode("ascii")
    # if fitbit.authorized:
    #     token = fitbit_bp.token["access_token"]
    #     del fitbit_bp.token
    #     resp = fitbit.post(
    #         "/oauth2/revoke",
    #         params={"token": token},
    #         headers={
    #             "Authorization": "Basic " + basic,
    #             "Content-Type": "application/x-www-form-urlencoded",
    #         },
    #     )
    #     return resp.content
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
            resp = fitbit.get("/1/user/-/profile.json")
            print(resp)
            print("access token: " + fitbit_bp.token["access_token"])
            print("refresh_token: " + fitbit_bp.token["refresh_token"])
            print("expiration time " + str(fitbit_bp.token["expires_at"]))
            print("             in " + str(fitbit_bp.token["expires_in"]))

        except Exception:
            print("exception")

        return "done"

    return "no active fitbit login"


if __name__ == "__main__":
    server_port = os.environ.get("PORT", "8080")
    app.run(debug=True, port=server_port, host="0.0.0.0")
