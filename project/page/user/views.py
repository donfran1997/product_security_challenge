import sqlite3, requests, json, os, re, jwt, string, random, logging
from flask import current_app, send_from_directory, Blueprint, flash, g, redirect, render_template, request, session, url_for
from flask_mail import Message
from flask_login import current_user, login_user, logout_user, login_required
from page import database, mail, bcrypt, csrf, talisman
from page.models import database, Users, Mfatoken
from page.util.security import generate_confirmation_token, confirm_token
from datetime import datetime
from password_validation import PasswordPolicy
from time import time

user = Blueprint('user', __name__, url_prefix='/')

'''
This function is used to send emails for 2fa and reset password token
'''
def send_email_reset(resetToken, email):
    msg = Message()
    msg.subject = 'Reset Password link'
    msg.recipients = email
    msg.sender = 'tt6370997@gmail.com'
    msg.body = "This is your reset password link: https://127.0.0.1:5000/resetPassword?token=" + resetToken.decode("UTF-8") + " .Please note that this link will expire in 10 minutes."
    mail.send(msg)

'''
generate potential password based on username. Just  Year and ! or @ and #
'''
def potent_pass(weakpassl, username):
    # will be geenrating password based on year appended with '!', '@' or '#' as it is more common
    for i in range(1970,2021):
        weakpassl.append(username.capitalize() + str(i) + "!")
        weakpassl.append(username.capitalize() + str(i) + "@")
        weakpassl.append(username.capitalize() + str(i) + "#")

    for i in range (70,21):
        weakpassl.append(username.capitalize() + str(i) + "!")
        weakpassl.append(username.capitalize() + str(i) + "@")
        weakpassl.append(username.capitalize() + str(i) + "#")

    return weakpassl

'''
Password stength checker function here.
Password will require to have 1 lowercase, uppercase, symbol and number charater.
No white space will be allowed in the password.
Minimum length for password will be 12 and max password is 48 to ensure that salting with bcrypt won't be an issue.
This poolicy should be enough to prevent all weak/known passwords.
In the case it isn't enough: username will have a small ruleset generated on it ensure a stronger password
and a custom wordlist has been genererated with known leaked password in xato-net-10-million-passwords-10000.txt 
using the InsidePro-PasswordsPro.rule to check for known and variations of known password
Used some bash scripting to remove the obvious all numbers or just lower or uppercase characters
'''
def password_strength(username, password):
    weakPass = []
    file = os.getcwd() + "/page/user/custom_known_pass.txt"
    with open(file) as f:
        weakPass = f.read().splitlines()
    f.close()
    # generate more passwords based of names
    weakPass = potent_pass(weakPass, username)
    policy = PasswordPolicy(lowercase=1, uppercase=1, symbols=1, numbers=1, whitespace=0, 
                            min_length=12, max_length=48, forbidden_words=weakPass)
    return policy.validate(password)

'''
Landing page is just some instruction s to register or login
'''
@csrf.exempt
@user.route('/')
def index():
    return render_template('landing.html')

'''
Check captcha helper function. Calls the google api to confirm is capture is valid 
'''
def check_captcha(g_recaptcha):
    # Get the captcha secret key via configs
    secret = current_app.config["RECAPTCHA_SECRET_KEY"]
    payload = {'response':g_recaptcha, 'secret':secret}
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", payload)
    response_text = json.loads(response.text)
    return response_text['success']

'''
Signup function
'''
@csrf.exempt
@user.route('/register', methods=('POST', 'GET'))
def register():
    # ensure current user isn't authenticated
    if current_user.is_authenticated:
        return redirect(url_for('user.signedin'))

    error = ''
    # get the POST data from the form
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        # we are lowercasing all chars in email to ensure the user don't get fancy
        # by uppercasing random chars to add the same email to db
        email = str.lower(email)
        password = request.form['password']
        cpassword = request.form['cpassword']
        g_recaptcha = request.form['g-recaptcha-response']

        #validate if captcha is done
        if not check_captcha(g_recaptcha):
            error += 'CAPTCHA was not selected'
            flash(error)
            return render_template('signup.html', sitekey=current_app.config["RECAPTCHA_SITE_KEY"])

        # now we need to check if sign up info is valid and not used
        error = ''
        userExist = Users.query.filter_by(username=username).first()
        emailExist = Users.query.filter_by(email=email).first()

        # check if email is in valid format
        email_re = '^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$'
        if not re.search(email_re, email):
            error += 'Email is in invalid format'

        # ensure that username and email hasn't been used before
        if userExist is not None or emailExist is not None:
            # use vauge messages to not disclose too much info
            error += '<br> Username or Email has been registered'

        # check to make sure both password supplied are the same
        if password != cpassword:
            error += '<br> Password provided are not the identical'

        # ensure that password is strong
        if not password_strength(username, password):
            error += '<br> Weak password - ensure to follow password policy'

        # can create account as all condition are met
        if error == '':
            # create a session to authenticate user password is automaticalled hashed in models.py
            newUser = Users(username, email, password, 0)
            database.session.add(newUser)
            database.session.commit()
            session.permanent = True
            login_user(newUser)
            return redirect(url_for('user.signedin'))
        flash(error)


    return render_template('signup.html', sitekey=current_app.config["RECAPTCHA_SITE_KEY"])

'''
This function is used to send emails for 2fa and reset password token
'''
def send_mfa_email(mfatoken, email):
    msg = Message()
    msg.subject = 'Your MFA code'
    msg.recipients = email
    msg.sender = 'tt6370997@gmail.com'
    msg.body = "This is your mfa code: " + mfatoken + " .Please note that it will expire in 90 seconds."
    mail.send(msg)

'''
Helper function to check if mfa code 
'''
def sendmfa(checkMfa):
    if checkMfa.mfa_enabled:
        # generate a MFA token and expiration time for it ~90sec
        mfatoken = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(7))
        #Generate session expiration time
        mfatime = str(time() + 90)
        newMfa = Mfatoken(mfatoken, checkMfa.username, mfatime)
        database.session.add(newMfa)
        database.session.commit()
        # grabbing the email of the person we need to need it to
        # flask mail uses a list so we will put it in a list
        email = Users.query.filter_by(username=checkMfa.username).first()
        emailingL = []
        emailingL.append(email.email)
        #let's email the mfa code to the user
        send_mfa_email(mfatoken, emailingL)
        return True
    return False

'''
Check to see if mfa is valid. Once valid we assign the session to the user
'''
@csrf.exempt
@user.route('/checkmfa', methods=('POST', 'GET'))
def checkmfa():
    #ensure that current user is not logged in
    if current_user.is_authenticated:
        return redirect(url_for('user.signedin'))

    error = ''
    if request.method == 'POST':
        mfacode = request.form['mfacode']
        g_recaptcha = request.form['g-recaptcha-response']

        # validate if captcha is done
        if not check_captcha(g_recaptcha):
            error += 'CAPTCHA was not selected'
            flash(error)
            return render_template('index.html', sitekey=current_app.config["RECAPTCHA_SITE_KEY"])

        checkMfa = Mfatoken.query.filter_by(mfacode=mfacode).first()
        # if mfa code has not expired log the user in
        if float(checkMfa.mfatime) - time() > 0:
            user = Users.query.filter_by(username=str(checkMfa.user)).first()
            login_user(user)
            return redirect(url_for('user.signedin'))
        error += 'Invalid MFA token'
        flash(error)

    return render_template("entermfa.html", sitekey=current_app.config["RECAPTCHA_SITE_KEY"])

'''
Login function
'''
@csrf.exempt
@user.route('/login', methods=('POST', 'GET'))
def login():
    # ensure that current user is not logged in
    if current_user.is_authenticated:
        return redirect(url_for('user.signedin'))

    # errors should be as vague as possible to not disclose any info to the attackers
    error = ''
    # ensure that form data is sent via POST otherwise breach of server logs can result attackers
    # seeing clear-text credentials
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        g_recaptcha = request.form['g-recaptcha-response']

        #validate if captcha is done
        if not check_captcha(g_recaptcha):
            error += 'CAPTCHA was not selected'
            flash(error)
            return render_template('index.html', sitekey=current_app.config["RECAPTCHA_SITE_KEY"])

        checkUser = Users.query.filter_by(username=username).first()
        # make sure checkUser is not None otherwise we will have errors
        if checkUser: 
            # check to make sure the hashed inputed password matches database
            if checkUser.check_password(password):
                # check if user has mfa enabled if yes send code and redirect
                # to page to enter the mfa code
                if sendmfa(checkUser):
                    return redirect(url_for('user.checkmfa'))
                else:
                    # setting this allows session token to automatically expire after 20 minutes
                    session.permanent = True
                    login_user(checkUser)
                    return redirect(url_for('user.signedin'))
            else:
                error += 'Username or Password is incorrect'
                flash(error)
                return render_template("index.html", sitekey=current_app.config["RECAPTCHA_SITE_KEY"])
        else:
            error += 'Username or Password is incorrect'

        # show the application user the vague message
        flash(error)

    # Create a captcha for rate limiting purposes on all login forms
    return render_template("index.html", sitekey=current_app.config["RECAPTCHA_SITE_KEY"])

'''
Helper function to create a JWT token that expires for password reset
doesn't require db usage and cheaper to do
'''
@csrf.exempt
def get_reset_token(current_user, expires=300):
    return jwt.encode({'reset_password': current_user.username, 'exp': time() + expires},
        key=os.getenv('SECRET_KEY'))

'''
Forgot password functionality
'''
@csrf.exempt
@user.route('/forgotPassword', methods=('POST', 'GET'))
def forgotPassword():
    # ensure that current user is not logged in
    if current_user.is_authenticated:
        return redirect(url_for('user.signedin'))

    # keep notification/error messages as vague as possible
    error = ""
    # ensure that form data is sent via POST otherwise breach of server logs can result attackers
    # seeing clear-text username may help in enumeration
    if request.method == 'POST':
        # can take username or email
        unorem = request.form['unorem']
        g_recaptcha = request.form['g-recaptcha-response']

        #validate if captcha is done
        if not check_captcha(g_recaptcha):
            error += '<br>CAPTCHA was not selected'
            flash(error)
            return render_template('forgotpass.html', sitekey=current_app.config["RECAPTCHA_SITE_KEY"])

        #check to see if username or email is valid
        email_re = '^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$'
        userCheck = None
        if re.search(email_re, unorem):
            userCheck = Users.query.filter_by(email=unorem).first()
        else:
            userCheck = Users.query.filter_by(username=unorem).first()

        #create a JWT token that expires after 5 minutes and send this to the user if valid
        if userCheck:
            resetToken = get_reset_token(userCheck)
            # get email list to send
            emailL = []
            emailL.append(userCheck.email)
            send_email_reset(resetToken, emailL)
        error += '<br>If the username/email exists you will recieve an email shortly'
        flash(error)

    return render_template('forgotpass.html', sitekey=current_app.config["RECAPTCHA_SITE_KEY"])


'''
Reset forgotten password functionality
'''
@csrf.exempt
@user.route('/resetPassword', methods=('POST', 'GET'))
def resetPassword():
    # these errors can be slightly more specific as they just relate to 
    # setting the password
    error = ''
    if request.method == 'POST':
        password = request.form['password']
        cpassword = request.form['cpassword']
        g_recaptcha = request.form['g-recaptcha-response']

        # validate if captcha is done
        if not check_captcha(g_recaptcha):
            error += '<br>CAPTCHA was not selected'
            flash(error)
            return render_template('forgotpass.html', sitekey=current_app.config["RECAPTCHA_SITE_KEY"])

        # validate that the password match
        token = request.args.get('token')
        if password != cpassword:
            error += '<br>Passwords do not match.'
            flash(error)
            return redirect('/resetPassword?token='+token)

        # decode and the username if jwt token is valid    
        username = jwt.decode(token, key=os.getenv('SECRET_KEY'))['reset_password']
        if not password_strength(username, password):
            error += '<br>Weak password - ensure to follow password policy'
            flash(error)
            return redirect('/resetPassword?token='+token)

        userPass = Users.query.filter_by(username=username).first()
        # when updating the password here I need to hash so that it isn't stored cleartext
        userPass.password = bcrypt.generate_password_hash(password, 15)
        database.session.commit()
        session.permanent = True
        login_user(userPass)
        return redirect(url_for('user.signedin'))


    try:
        # get the token and see if it is valid
        if request.method == 'GET':
            token = request.args.get('token')
            # validate that the JWT is valid to authorise the password reset
            validateUser = jwt.decode(token, key=os.getenv('SECRET_KEY'))
            return render_template('resetpass.html', sitekey=current_app.config["RECAPTCHA_SITE_KEY"])
    except jwt.ExpiredSignature:
        error += 'Invalid token provided.'
        flash(error)
        return render_template("index.html", sitekey=current_app.config["RECAPTCHA_SITE_KEY"])
    flash(error)
    return render_template('resetpass.html', sitekey=current_app.config["RECAPTCHA_SITE_KEY"])

'''
This area is entirely for authenticated functions.
login_required will be used in order to ensure correct authorisation is in place
'''

'''
Simple dashboard for authed user to enable mfa if they want
'''
@user.route('/dashboard', methods=('POST', 'GET'))
@login_required
def signedin():
    if request.method == 'POST':
        if current_user.mfa_enabled:
            print(current_user.mfa_enabled)
            disable_mfa()
        else:
            enable_mfa()
    return render_template('dashboard.html', username=current_user.username, mfaset=current_user.mfa_enabled)

'''
Log user out and destroy the session token
'''
@user.route('/logout')
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for('user.index'))

'''
Turn MFA on
'''
def enable_mfa():
    userMfa = Users.query.filter_by(username=current_user.username).first()
    userMfa.mfa_enabled = 1
    database.session.commit()
    return redirect(url_for('user.signedin'))

'''
Turn MFA off
'''
def disable_mfa():
    userMfa = Users.query.filter_by(username=current_user.username).first()
    userMfa.mfa_enabled = 0
    database.session.commit()
    return redirect(url_for('user.signedin'))
