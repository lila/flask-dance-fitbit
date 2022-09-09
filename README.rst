Flask-Dance Example App: Fitbit Edition
=======================================

This repository provides an complete example of how to use `Flask-Dance`_,
`Flask_login`_, `Fitbit`_, and `Google Cloud Firestore`_ to allow authenticated
users to connect their login to their Fitbit identity.  The minimal code
uses `Flask_login`_ to with a local login manager to authenticate users
(the code only has 2 users, ``user1`` and ``user2`` but you can add others).

As users login and consent, the tokens will be created; when users signout
of the Fitbit consent, those tokens will be deleted (but not revoked).

User Flow:
----------

1. user goes to the site index ``/``  and is presented with login and
fitbit auth status or ``unauthorized`` if not logged in::

    "unauthorized"

2. user goes to ``/login`` to authenticate to the site using ``flask_login``,
specifies *user1/secret* or *user2/secret* to login and is redirected
back to index ``/`` which should now say::

    "logged in as user1 Fitbit: false"

3. user goes to ``/fitbitlogin`` to associate fitbit login with user login.
user will be presented with standard oauth process and then is
redirected back to index ``/`` this time with a message::

    "logged in as user1 Fitbit: true"

4. At this point, the backend firecloud storage will have a document
called ``user1`` with the auth tokens to access fitbit.  to test,
go to ``/fitbittest`` and this should return the raw profile information
in json format.

5. test batch action by going to ``/allfitbitusers`` which will cycle through
all the user fitbit tokens and retrieve profile information from each.
the page will just show an python list of users with associated profile
info::

    [
      "user1: <fitbit user fullname> (MALE/25)",
      "user2: <fitbit user fullname> (FEMALE/42)"
    ]

6. to disassociated the fitbit account with the user account, go to
``/fitbitlogout``.  this will delete the backend token in firecloud and
redirect back to index ``/`` which will say that fibit is false::

    Logged in as: user1: fitbit: False

7. to leave the associate in place, but logout of the website, go to
"/logout" which will log the user out.  if you log in again, the
fitbit association will still be there.


to setup
--------

1. set up environment in .env (see .env-example for template)

2. get a GCP service account json file and store as service-account.json

3. setup the python environment using vscode/devcontainers or
venv

3. run % flask run to deploy application to localhost

Once the application is running, the following paths are available::

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


Get OAuth credentials from Fitbit
-----------------------------------------
Visit https://dev.fitbit.com/ to register an
application on fitbit. You must set the application's authorization
callback URL to ``https://localhost:5000/login/fitbit/authorized``.

Once you've registered your application on fitbit, fitbit will give you a
client ID and client secret, which we'll use in step 3.

Step 2: Install code and dependencies
-------------------------------------
Run the following commands on your computer::

    git clone https://fitbit.com/lila/flask-dance-fitbit.git
    cd flask-dance-fitbit
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

These commands will clone this git repository onto your computer,
create a `virtual environment`_ for this project, activate it, and install
the dependencies listed in ``requirements.txt``.

Step 3: Set environment variables
---------------------------------
Many applications use `environment variables`_ for configuration, and
Flask-Dance is no exception. You'll need to set the following environment
variables:

* ``FLASK_APP``: set this to ``fitbit.py``
* ``FITBIT_OAUTH_CLIENT_ID``: set this to the client ID you got
  from fitbit.
* ``FITBIT_OAUTH_CLIENT_SECRET``: set this to the client secret
  you got from fitbit.
* ``OAUTHLIB_INSECURE_TRANSPORT``: set this to ``true``. This indicates that
  you're doing local testing, and it's OK to use HTTP instead of HTTPS for
  OAuth. You should only do this for local testing.
  Do **not** set this in production! [`oauthlib docs`_]

The easiest way to set these environment variables is to define them in
an ``.env`` file. You can then install the `python-dotenv`_ package
to make Flask automatically read this file when you run the dev server.
This repository has a ``.env.example`` file that you can copy to
``.env`` to get a head start.

Run your app and login with fitbit!
-------------------------------------------
Run your app using the ``flask`` command::

    flask run

Then, go to http://localhost:5000/ to visit your app and log in with fitbit!

If you get an error message that says "Could not locate a Flask application",
then you need to install the `python-dotenv`_ package using ``pip``::

    pip install python-dotenv

Once the package is installed, try the ``flask run`` command again!

Learn more!
```````````
`Fork this fitbit repo`_ so that you can make changes to it. Read the
documentation for `Flask`_ and `Flask-Dance`_ to learn what's possible.
Ask questions, learn as you go, build your own OAuth-enabled web application,
and don't forget to be awesome!


.. _Flask_login:
.. _google cloud firestore:

.. _Flask: http://flask.pocoo.org/docs/
.. _Flask-Dance: http://flask-dance.readthedocs.org/
.. _fitbit: https://fitbit.com/
.. _Heroku: https://www.heroku.com/
.. _environment variables: https://en.wikipedia.org/wiki/Environment_variable
.. _python-dotenv: https://fitbit.com/theskumar/python-dotenv
.. _oauthlib docs: http://oauthlib.readthedocs.org/en/latest/oauth2/security.html#envvar-OAUTHLIB_INSECURE_TRANSPORT
.. _virtual environment: https://docs.python.org/3.7/library/venv.html
.. _Fork this fitbit repo: https://help.fitbit.com/articles/fork-a-repo/

.. |heroku-deploy| image:: https://www.herokucdn.com/deploy/button.png
   :target: https://heroku.com/deploy
   :alt: Deploy to Heroku
