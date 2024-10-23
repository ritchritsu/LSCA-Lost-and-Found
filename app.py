import os
import re  # To use regular expressions for email format validation
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import login_required, lookup, usd

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

@app.route("/submit", methods=["POST"])
@login_required
def submit_item():
    """Submit a lost or found item"""
    # Get data from the form
    description = request.form.get("description")
    category = request.form.get("category")
    location_lost = request.form.get("location_lost")
    location_found = request.form.get("location_found")
    date_lost = request.form.get("date_lost")
    date_found = request.form.get("date_found")
    status = request.form.get("status")  # 'lost' or 'found'
    image_url = request.form.get("image_url")  # optional

    # Basic validation for empty fields
    if not description or not category or not status:
        flash("All fields are required")
        return redirect("/")

    # Insert into the database
    db.execute("INSERT INTO items (description, category, location_lost, location_found, date_lost, date_found, status, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
               description, category, location_lost, location_found, date_lost, date_found, status, image_url)

    flash("Item submitted successfully!")
    return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()  # Clear any existing user session

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        
        if not email:
            flash("Please provide an email")
            return render_template("login.html")
        
        if not password:
            flash("Please provide a password")
            return render_template("login.html")

        rows = db.execute("SELECT * FROM users WHERE email = ?", email)

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            flash("Invalid email or password")
            return render_template("login.html")
            
        session["user_id"] = rows[0]["id"]
        flash("Logged in successfully!")
        return redirect("/")
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""
    session.clear()
    flash("You have been logged out.")
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check if email is valid using regex
        if not email or not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email format")
            return render_template("register.html")

        # Ensure password length is at least 8 characters
        if not password or len(password) < 8:
            flash("Password must be at least 8 characters long")
            return render_template("register.html")

        if password != confirmation:
            flash("Password and confirmation do not match")
            return render_template("register.html")

        # Check if email is already registered
        rows = db.execute("SELECT * FROM users WHERE email = ?", email)
        if len(rows) > 0:
            flash("This email is already registered")
            return render_template("register.html")

        # Hash the password
        hashed_password = generate_password_hash(password)

        try:
            db.execute("INSERT INTO users (email, hash) VALUES (?, ?)", email, hashed_password)
            flash("Registration successful!")
            return redirect("/login")
        except:
            flash("An error occurred during registration")
            return render_template("register.html")
    
    return render_template("register.html")

@app.route("/found")
@login_required
def found_items():
    """Show all found items"""
    items = db.execute("SELECT * FROM items WHERE status = 'found'")  # Retrieve found items
    return render_template("found-items.html", items=items)

if __name__ == "__main__":
    app.run(debug=True)
