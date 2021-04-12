from flask import Flask, request, render_template, jsonify
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from page import database
import logging, uuid, os, traceback
from logging.handlers import RotatingFileHandler
from time import strftime
from flask_wtf.csrf import CsrfProtect
from flask_talisman import Talisman
from datetime import timedelta

# this is used to initialise the db, mailing server, encryption, login function and csrf protection
login_manager = LoginManager()
database = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
mail = Mail()
csrf = CsrfProtect()
talisman = Talisman()

# setting up the loggin to timestamp what ip is seeing what
logger = logging.getLogger(__name__)
handler = RotatingFileHandler('app.log', maxBytes=100000, backupCount=3)
logger = logging.getLogger('tdm')
logger.setLevel(logging.ERROR)
logger.addHandler(handler)

# this is setting up the CSP Policy
csp = {
    'default-src': [
        '\'self\'',
        '\'unsafe-inline\'',
        'www.google.com',
        'maxcdn.bootstrapcdn.com',
        'www.gstatic.com',
        'ajax.googleapis.com',
        'cdnjs.cloudflare.com',
        'stackpath.bootstrapcdn.com',
        'code.jquery.com',
        'cdn.jsdelivr.net'
    ],
     'script-src': '*',
     "style-src": [
        '\'self\'',
        '\'unsafe-inline\'',
        'www.google.com',
        'maxcdn.bootstrapcdn.com',
        'www.gstatic.com',
        'ajax.googleapis.com',
        'cdnjs.cloudflare.com',
        'stackpath.bootstrapcdn.com',
        'code.jquery.com',
        'cdn.jsdelivr.net']

}

DATABASE = '../user.db'
app = Flask(__name__, instance_relative_config=False)

# After each request do the logs for which IP visited along with what path and status code
@app.after_request
def after_request(response):
    timestamp = strftime('[%Y-%b-%d %H:%M]')
    logger.error('%s %s %s %s %s %s', timestamp, request.remote_addr, request.method, request.scheme, request.full_path, response.status)
    return response

# Having server header out results in information leakage
@app.after_request
def remove_header(response):
    del response.headers['X-Content-Type-Options']
    response.headers['Server'] = "."

    return response

# This is to create custom error page to not reveal what
# the back end is potentially or what language is in use
@app.errorhandler(400)
def bad_request(e):
    return render_template("400.html"), 400

@app.errorhandler(401)
def forbidden_access(e):
    return render_template("401.html"), 401

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(405)
def bad_method(e):
    return render_template('405.html'), 405

@app.errorhandler(429)
def long_URL(e):
    return render_template('429.html'), 429

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500

def create_app():
    #setting up Flask variables to ensure everything works
    app.config.update(
        # mail server set up
        MAIL_SERVER = 'smtp.gmail.com',
        MAIL_PORT = 587,
        MAIL_USE_SSL = False,
        MAIL_USE_TLS = True,
        MAIL_USERNAME = "tt6370997@gmail.com",
        MAIL_PASSWORD = ",AH28D}gZcn2qKx?",

        # captcha set up
        RECAPTCHA_ENABLED = True,
        RECAPTCHA_SITE_KEY = "6Lc9AqUaAAAAAJydDlbepk44I4XePwRTG6ZsGGLL",
        RECAPTCHA_SECRET_KEY = "6Lc9AqUaAAAAAFmP_mq9t4aHd5Th_a3Cfkjy6Tqd",

        # setting expiration for CSRF token in secs
        WTF_CSRF_TIME_LIMIT = 60,

        # setting up cookie expiration to something safe ~20minutes
        # cookie does auto httponly which is good against XSS attack
        # let's set it secure as well so it is only sent in encrypted transmission
        PERMANENT_SESSION_LIFETIME =  timedelta(minutes=20),
        SESSION_COOKIE_SECURE = True,
        REMEMBER_COOKIE_SECURE = True

    )

    app.config.from_object('config.Config')
    app.config.from_object(__name__)
    # this is used for linking helper objects with current Flask apps
    mail.init_app(app)
    login_manager.init_app(app)
    database.init_app(app)
    migrate.init_app(app, database)
    csrf.init_app(app)
    talisman.init_app(app, content_security_policy=csp)

    # registering the custom error
    app.register_error_handler(400, bad_request)
    app.register_error_handler(401, forbidden_access)
    app.register_error_handler(404, page_not_found)
    app.register_error_handler(405, bad_method)
    app.register_error_handler(429, long_URL)
    app.register_error_handler(500, server_error)

    with app.app_context():
        from page.user.views import user
        app.register_blueprint(user)
        database.create_all()

        return app