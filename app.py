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



# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///app.db")


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
    """Show found and lost items"""
    found_items = db.execute("SELECT * FROM items WHERE status = 'found'")  # Retrieve all found items
    lost_items = db.execute("SELECT * FROM items WHERE status = 'lost'")    # Retrieve all lost items

    return render_template("index.html", found_items=found_items, lost_items=lost_items)



@app.route("/submit", methods=["GET", "POST"])
@login_required
def submit_item():
    if request.method == "POST":
        # Get data from the form
        description = request.form.get("description")
        category = request.form.get("category")
        location_lost = request.form.get("location_lost")
        location_found = request.form.get("location_found")
        date_lost = request.form.get("date_lost")
        date_found = request.form.get("date_found")
        status = request.form.get("status")  # 'lost' or 'found'
        image_url = request.form.get("image_url")  # optional

        # Insert into the database
        db.execute("INSERT INTO items (description, category, location_lost, location_found, date_lost, date_found, status, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   description, category, location_lost, location_found, date_lost, date_found, status, image_url)

        flash("Item submitted successfully!")  # Use flash to notify the user
        return redirect("/")

    return render_template("submit_item.html")  # Render the submission form


@app.route("/found")
@login_required
def history():
    """Show all found items"""
    # Retrieve all found items
    found_items = db.execute("SELECT * FROM items WHERE status = 'found'")

    return render_template("found-items.html", found_items=found_items)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()  # Clear any existing user session

    if request.method == "POST":
        email = request.form.get("email")  # Get email from form
        if not email:
            return apology("must provide email", 403)  # Ensure email is provided

        if not request.form.get("password"):
            return apology("must provide password", 403)  # Ensure password is provided

        # Query the database for the provided email
        rows = db.execute("SELECT * FROM users WHERE email = ?", email)

        # Ensure email exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid email and/or password", 403)  # If not valid, return error

        session["user_id"] = rows[0]["id"]  # Store user ID in session
        return redirect("/")  # Redirect to homepage upon successful login

    return render_template("login.html")  # Render the login template for GET requests


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
        email = request.form.get("email")  # Get email instead of username
        if not email:
            return apology("email is blank")
        
        # Check if email is already registered
        rows = db.execute("SELECT * FROM users WHERE email = ?", email)
        if len(rows) > 0:
            return apology("this email is already registered")

        # Check for password and confirmation
        if not request.form.get("password"):
            return apology("password is blank")
        
        if request.form.get("confirmation") != request.form.get("password"):
            return apology("passwords do not match")
        
        hashed_password = generate_password_hash(request.form.get("password"))
        try:
            # Insert user with email instead of username
            db.execute("INSERT INTO users (email, hash) VALUES (?, ?)", email, hashed_password)
            return redirect("/login")
        except:
            return apology("error occurred during registration")
    
    return render_template("register.html")

@app.route("/add_item", methods=["GET", "POST"])
@login_required
def add_item():
    if request.method == "POST":
        description = request.form.get("description")
        container = request.form.get("container")
        category = request.form.get("category")
        location_lost = request.form.get("location_lost")
        location_found = request.form.get("location_found")
        date_lost = request.form.get("date_lost")
        date_found = request.form.get("date_found")
        status = request.form.get("status")  # Make sure this is set to "lost" or "found"
        image_url = request.form.get("image_url")

        # Set final variables based on item status
        if status == "lost":
            # For lost items, set location_found and date_found to None
            final_location_lost = location_lost
            final_location_found = None  # Explicitly set to None
            final_date_lost = date_lost
            final_date_found = None  # Explicitly set to None
        elif status == "found":
            # For found items, set location_lost and date_lost to None
            final_location_lost = None  # Explicitly set to None
            final_location_found = location_found
            final_date_lost = None  # Explicitly set to None
            final_date_found = date_found

        # Insert item into the database
        db.execute("INSERT INTO items (description, container, category, location_lost, location_found, date_lost, date_found, status, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   description, container, category, final_location_lost, final_location_found, final_date_lost, final_date_found, status, image_url)

        return redirect("/found")

    return render_template("add_item.html")


@app.route("/found")
@login_required
def found_items():
    """Show all found items"""
    items = db.execute("SELECT * FROM items WHERE status = 'found'")  # Retrieve found items
    return render_template("found_items.html", items=items)

@app.route("/lost")
@login_required
def lost_items():
    """Show all lost items"""
    items = db.execute("SELECT * FROM items WHERE status = 'lost'")  # Retrieve lost items
    return render_template("lost_items.html", items=items)