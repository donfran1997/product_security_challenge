from flask import current_app as app
from itsdangerous import URLSafeTimedSerializer
import uuid

salt_val = str(uuid.uuid4())

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return serializer.dumps(email, salt=salt_val)


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = serializer.loads( \
            token,
            salt=salt_val,
            max_age=expiration)
    except:
        return False

    return email
