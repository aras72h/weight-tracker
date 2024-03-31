import os
from datetime import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///weight_tracker.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    weights = db.execute('SELECT * FROM weights WHERE user_id = ? ORDER BY date DESC;',
                          session['user_id'])
    this_month = int(datetime.now().month)
    this_year =  int(datetime.now().year)
    
    if this_month == 1:
        last_month = 12
        this_year -= 1
    else:
        last_month = this_month - 1

    date_start = f'{this_year}-{last_month:02d}-01'
    date_end = f'{this_year}-{last_month:02d}-31'

    # Calculate last month average
    last_month_avg = db.execute('SELECT avg(weight) AS avg_weight FROM weights WHERE user_id = ? AND date BETWEEN ? AND ?;',
                                session['user_id'],
                                date_start,
                                date_end)
    avg_last = last_month_avg[0]['avg_weight'] if last_month_avg else None

    # Calculate this month average
    this_month_avg = db.execute('SELECT avg(weight) AS avg_weight FROM weights WHERE user_id = ? AND date BETWEEN ? AND ?;',
                                session['user_id'],
                                f'{this_year}-{this_month:02d}-01',
                                f'{this_year}-{this_month:02d}-31')
    avg_current = this_month_avg[0]['avg_weight'] if this_month_avg else None

    return render_template('index.html', weights=weights, avg_last=avg_last, avg_current=avg_current)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == 'POST':
        date = request.form.get('date')
        weight = float(request.form.get('weight'))
        db.execute('INSERT INTO weights (user_id, weight, date) VALUES (?, ?, ?);',
                    session['user_id'], weight, date)
        return redirect('/')
    else:
        return render_template('add.html')


@app.route("/history", methods=["GET"])
@login_required
def history():
    weights = db.execute('SELECT * FROM weights WHERE user_id = ? ORDER BY date DESC;',
                          session['user_id'])
    return render_template('history.html', weights=weights)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?;",
                           request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Storing user's input into variables
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        hash = generate_password_hash(password)
        # Checking for correct input from user
        if not (username and password and confirmation):
            return apology("all fields required")
        else:
            # Check username to be unique
            rows = db.execute("SELECT * FROM users WHERE username = ?;", username)
            if len(rows) != 0:
                return apology("username already exists")
            # Compare password and its confirmation
            elif password != confirmation:
                return apology("confirm your password correctly")
            else:
                # Insert user info into database
                db.execute("INSERT INTO users (username, hash) values (?, ?);",
                            username, hash)
                return redirect("/login")
    else:
        return render_template("register.html")
