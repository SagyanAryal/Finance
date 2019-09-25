# Sagyan Aryal
# PSET 8 Finance
# 4/18/19

import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    userCash = db.execute("SELECT cash from users WHERE id = :user_id", user_id=session["user_id"])
    userCash = userCash[0]["cash"]
    
    portfolio = db.execute(
        "SELECT symbol, SUM(shares) as totalShares, price FROM transactions WHERE user_id = :user_id GROUP BY symbol", user_id=session["user_id"])
    return render_template("index.html", portfolio=portfolio, userCash=userCash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        
        quote = lookup(request.form.get("symbol"))
    
        if not quote:
            return apology("Not valid", 400)
            
        try:
            symbol = lookup(request.form.get("symbol"))
            shares = int(request.form.get("shares"))
        except:
            return apology("Not valid")
        
        if shares < 0:
            return apology("Not valid number")
        
        userCash = db.execute("SELECT cash from users WHERE id = :user_id", user_id=session["user_id"])
        userCash = userCash[0]["cash"]
        cost = shares * quote["price"]
        
        if userCash < cost:
            return apology("Cannot afford")
        
        db.execute("UPDATE users SET cash = cash - :cost WHERE id = :user_id", cost=cost, user_id=session["user_id"])
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)",
                   user_id=session["user_id"], symbol=request.form.get("symbol"), shares=shares, price=symbol['price'])

        return redirect("/")
    
    else:
        return render_template("buy.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    
    username = request.args.get("username")
    name = db.execute("SELECT username FROM users WHERE username = :username", username=username)
    if not name:
        return jsonify(True)
    else:
        return jsonify(False)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute(
        "SELECT symbol, shares, price, timestamp FROM transactions WHERE user_id = :user_id", user_id=session["user_id"])
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))
    
        if not quote:
            return apology("Error while searching for stock", 400)
    
        return render_template("displayQuote.html", quote=quote)
    
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)
        
        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("must provide password", 400)
            
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords don't match", 400)
            
        hash = generate_password_hash(request.form.get("password"))
        
        result = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
                            username=request.form.get("username"), hash=hash)
        
        if not result:
            return apology("Username already exists", 400)
        else:
            return apology("completed", 200)
    
        session["user_id"] = result
        return redirect("/")
    
    else:
        return render_template("register.html")


@app.route("/resetPassword", methods=["GET", "POST"])
def resetPassword():
    """Register user"""
    
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        if not request.form.get("username"):
            return apology("must provide username", 400)
            
        if not request.form.get("currentPassword"):
            return apology("must provide currentPassword", 400)
        
        elif not request.form.get("newPassword") or not request.form.get("confirmedNewPassword"):
            return apology("must provide password", 400)
            
        elif request.form.get("newPassword") != request.form.get("confirmedNewPassword"):
            return apology("Passwords don't match", 400)
            
        hash = generate_password_hash(request.form.get("newPassword"))
        result = db.execute("UPDATE users SET hash = :hash WHERE id = :user_id", user_id=session["user_id"], hash=hash)
        
        session["user_id"] = result
        return redirect("/")
    
    else:
        return render_template("resetPassword.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    
    if request.method == "POST":
        quota = lookup(request.form.get("symbol"))
    
        if not quota:
            return apology("Not valid", 400)
            
        try:
            symbol = lookup(request.form.get("symbol"))
            shares = int(request.form.get("shares"))
        except:
            return apology("Not valid")
            
        if shares <= 0:
            return apology("Not valid number")
        
        stock = db.execute("SELECT SUM(shares) as total_shares FROM transactions WHERE user_id = :user_id AND symbol = :symbol GROUP BY symbol",
                           user_id=session["user_id"], symbol=request.form.get("symbol"))
        
        if stock[0]["total_shares"] < shares or stock[0]["total_shares"] <= 0:
            return apology("Invalid")
            
        total = quota["price"] * shares
        db.execute("UPDATE users SET cash = cash + :total WHERE id = :user_id", user_id=session["user_id"], total=total)
        db.execute("INSERT INTO 'transactions' (user_id, symbol, shares, price) VALUES(:user_id, :symbol, :shares, :price)",
                   user_id=session["user_id"], symbol=request.form.get("symbol"), shares=-shares, price=symbol["price"])
        return redirect("/")
    else:

        currentStocks = db.execute(
            "SELECT symbol, SUM(shares) as total_shares FROM transactions WHERE user_id = :user_id GROUP BY symbol", user_id=session["user_id"])
        return render_template("sell.html", currentStocks=currentStocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
