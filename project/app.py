from page import create_app
from flask import session
from flask_mail import Mail
from flask_recaptcha import ReCaptcha
from database import *
import os
import uuid

app = create_app()
# secret here is used to generate CSRF token along with session token
# I have no idea of the key so the attacker must not as well :D
app.secret_key = str(uuid.uuid4())

if __name__ == '__main__':
	# Runs with ssl uses self-signed cert in the real world you would like to buy a trusted
	# vert of a trusted provider and debug off to not leak info
    app.run(host='0.0.0.0', ssl_context='adhoc', debug=False)
    init_db(r"user.db")
