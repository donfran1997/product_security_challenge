from page import database, bcrypt
from datetime import datetime
from sqlalchemy.ext.hybrid import hybrid_property

# Model  for the Users
class Users(database.Model):
    __tablename__ = 'users'

    id = database.Column(database.Integer, primary_key=True)
    username = database.Column(database.Text, nullable=False)
    email = database.Column(database.Text, nullable=False)
    password = database.Column(database.Text, nullable=False)
    mfa_enabled = database.Column(database.Integer, nullable=False)


    # these properties are for logged in users
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    # passwords should be stored encrypted with a cryptographically safe algorithm
    # with the use of salt to make it harder to an attacker to "decrypt"
    def hash_password(self, password):
        # using 15 rounds of bcrypt magic
        self.password = bcrypt.generate_password_hash(password, 15)
        
    # used to check if inputed password matches stored hashed password
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def __init__(self, username, email, password, mfa_enabled):
        self.username = username
        self.email = email
        self.hash_password(password)
        self.mfa_enabled = mfa_enabled

    def __repr__(self):
        returnStr = str('Account name: %s\n') % (self.username)
        return returnStr

# Model for mfatokens
class Mfatoken(database.Model):
    __tablename__ = 'mfatoken'

    id = database.Column(database.Integer, primary_key=True)
    mfacode = database.Column(database.Text, nullable=False)
    user = database.Column(database.Text, nullable=False)
    mfatime = database.Column(database.Text, nullable=False)

    def __init__ (self, mfacode, user, mfatime):
        self.mfacode = mfacode
        self.user = user
        self.mfatime = mfatime

from page.util.login_manager import *
