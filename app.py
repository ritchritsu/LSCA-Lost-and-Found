import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates auto-reload
app.config['TEMPLATES_AUTO_RELOAD'] = True




# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    """Show portfolio of stocks"""
    stocks = db.execute("SELECT * FROM purchases WHERE user_id = ?", session["user_id"])
    print(stocks)

    return render_template("index.html", stocks = stocks)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        # Validate form data
        if not symbol:
            return apology("please enter a symbol!")

        if not shares or not shares.isdigit() or int(shares) <= 0:
            return apology("please enter a positive integer!")
        shares = int(shares)

        # Look up the stock quote
        quote = lookup(symbol)
        if not quote:
            return apology("Invalid Symbol")

        # Calculate total price
        total_price = shares * quote['price']



        # Retrieve user's cash balance
        rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = rows[0]['cash']

        # Check if the user can afford the purchase
        if cash < total_price:
            return apology("Sorry, you cannot afford this")

        # Update user's cash balance and record the purchase
        new_cash = cash - total_price
        try:
            # Update user's cash balance
            db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, session["user_id"])
            # Insert purchase record
            db.execute("INSERT INTO purchases (user_id, stock_symbol, purchase_price, shares, total) VALUES (?,?,?,?,?)", session["user_id"], symbol, quote['price'], shares, total_price)
            # Record transaction
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            transaction_type = "Buy"
            db.execute("INSERT INTO transactions (user_id, stock_symbol, shares, price_per_share, total, timestamp, transaction_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    session["user_id"], symbol, shares, quote["price"], total_price, timestamp, transaction_type)
        except Exception as e:
            # Handle any errors that may occur during database operations
            return apology("Error occurred while processing your request")

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/found")
@login_required
def history():

    return render_template("found-items.html")


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("please enter a symbol!")
        quote = lookup(symbol)
        if not quote:
            return apology("Invalid Symbol")
        else:
            return render_template("quoted.html", quote = quote)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("username is blank")
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(rows) > 0:

            return apology("this username already exists")
        else:

            if not request.form.get("password"):
                return apology("password is blank")
        if request.form.get("confirmation") != request.form.get("password"):
            return apology("passwords do not match")
        hashed_password = generate_password_hash(request.form.get("password"))
        try:
            db.execute("INSERT INTO users(username, hash) VALUES (?,?)", request.form.get("username"), hashed_password)
            return redirect("/login")
        except:
            return apology("user has already been registered!")
    if request.method == "GET":
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
def sell():
    # Sell stocks
    if request.method == "POST":
        # Check if user is logged in
        if "user_id" not in session:
            return redirect("/login")

        # Retrieve form data
        symbol = request.form.get("symbol").upper()
        shares = int(request.form.get("shares"))

        # Validate form data
        if not symbol:
            return apology("must provide stock symbol")
        if not shares:
            return apology("must provide number of shares")

        # Check if user has enough shares to sell
        user_id = session["user_id"]
        purchase = db.execute("SELECT * FROM purchases WHERE user_id = ? AND stock_symbol = ?", user_id, symbol)
        if not purchase:
            return apology("you don't own any shares of this stock")
        elif shares > purchase[0]["shares"]:
            return apology("you don't have that many shares to sell")

        # Lookup current stock price
        stock_info = lookup(symbol)
        if not stock_info:
            return apology("stock symbol not found")

        # Calculate total sale value
        sale_value = shares * stock_info['price']




        # Update user's cash balance
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]
        new_cash_balance = user_cash + sale_value
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash_balance, user_id)

        # Update stock purchase record
        remaining_shares = purchase[0]["shares"] - shares
        if remaining_shares == 0:
            db.execute("DELETE FROM purchases WHERE id = ?", purchase[0]["id"])
        else:
            db.execute("UPDATE purchases SET shares = ? WHERE id = ?", remaining_shares, purchase[0]["id"])

        # Record sale transaction
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        transaction_type = "Sell"
        db.execute("INSERT INTO transactions (user_id, stock_symbol, shares, price_per_share, total, timestamp, transaction_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   user_id, symbol, -shares, stock_info["price"], sale_value, timestamp, transaction_type)

        return redirect("/")

    else:
        # Retrieve user's stock holdings
        user_id = session["user_id"]
        holdings = db.execute("SELECT * FROM purchases WHERE user_id = ?", user_id)
        return render_template("sell.html", holdings=holdings)

