from page import login_manager
from page.models import Users
from flask_login import current_user
from flask import render_template


@login_manager.user_loader
def load_user(user):
    if user is not None:
        return Users.query.get(user)
    return None


@login_manager.unauthorized_handler
def unauthorized():
    return render_template("401.html"), 401
