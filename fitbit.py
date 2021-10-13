import os
import base64
from flask import Flask, redirect, url_for
from flask_dance.contrib.fitbit import make_fitbit_blueprint, fitbit


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit")
app.config["FITBIT_OAUTH_CLIENT_ID"] = os.environ.get("FITBIT_OAUTH_CLIENT_ID")
app.config["FITBIT_OAUTH_CLIENT_SECRET"] = os.environ.get("FITBIT_OAUTH_CLIENT_SECRET")
fitbit_bp = make_fitbit_blueprint(scope=['activity','profile'])
app.register_blueprint(fitbit_bp, url_prefix="/login")


@app.route("/")
def index():
    if not fitbit.authorized:
        return redirect(url_for("fitbit.login"))
    #s = fitbit_bp.client_id + ":" + fitbit_bp.client_secret
    #basic = base64.b64encode(s.encode("ascii")).decode('ascii')
    #fitbit_bp.auto_refresh_kwargs = {
    #    "Authorization": "Basic " + basic,
    #    "Content-Type": "application/x-www-form-urlencoded"
    #}
    resp = fitbit.get(
        "/1/user/-/profile.json",
        headers={
            "Authorization" : "Bearer " + fitbit_bp.token["access_token"]
        }
    )
    return(resp.content)
    #return "You are @{login} on Fitbit".format(login=resp.json()["login"])

@app.route("/logout")
def logout():
    s = fitbit_bp.client_id + ":" + fitbit_bp.client_secret
    basic = base64.b64encode(s.encode("ascii")).decode('ascii')
    if fitbit.authorized:
        token = fitbit_bp.token["access_token"]
        del fitbit_bp.token
        resp = fitbit.post(
            "/oauth2/revoke",
            params={"token": token},
            headers={
                "Authorization": "Basic " + basic,
                "Content-Type": "application/x-www-form-urlencoded"
            }
        )
        return resp.content
    return "not logged in"