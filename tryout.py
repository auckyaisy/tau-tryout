import os
import datetime
import re

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///data.db")


@app.route("/")
@login_required
def index(): 
    flash("todo")
    return render_template(index.html)

# @app.route("/tryout")
# @login_required
# def

@app.route("/login")
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            flash("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("must provide password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("invalid username and/or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]

        # Redirect user to home page
        flash("Success Login!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reach route via POST (submitting via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            flash("must provide username")

        username = request.form.get("username")
        if check_user(username) == False:
            flash("Username has been taken, please use another else")
            return render_template("register.html")

        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("must provide password")

         # Ensure password was submitted
        elif not request.form.get("confirm"):
            flash("must provide password")

        if request.form.get("confirm") != request.form.get("password"):
            flash("the confiration must be same with the password")

        password = request.form.get("password")

        if check_pass(password) == False:
            flash("Please Make The Password Following The Rules!")
            return render_template("register.html")

         # Inserting to database for username
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)",
                   username=request.form.get("username"), password=generate_password_hash(request.form.get("password")))

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash("Registered!")
        return redirect("/")

     # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


def check_pass(password):
    """Checking The Password Meet The Rules"""

    # making flag for checking
    flag = 0

    while True:

        # check the lenght
        if (len(password) < 8):
            flag = -1
            break
        # check the lowercase
        elif not re.search("[a-z]", password):
            flag = -1
            break
        # check the uppercase
        elif not re.search("[A-Z]", password):
            flag = -1
            break
        # check the number
        elif not re.search("[0-9]", password):
            flag = -1
            break
        else:
            # if all meet the rules then return true
            flag = 0
            return True

    # else returning false
    if flag == -1:
        return False

def check_user(username):
    check = db.execute("SELECT username FROM users WHERE username = :username", username=username)
    if len(check) == 1:
        return False
    else:
        return True
