import os
import re
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import login_required

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
    """Show submission form or admin dashboard based on user"""
    user_email = db.execute("SELECT email FROM users WHERE id = ?", session["user_id"])[0]["email"]

    if user_email == "ritchangelo.dacanay@lsca.edu.ph":
        items = db.execute("SELECT * FROM items")
        return render_template("admin-dashboard.html", items=items)
    else:
        return render_template("submission.html")

@app.route("/submit", methods=["POST"])
@login_required
def submit_item():
    """Submit a lost item"""
    lost_date = request.form.get("lost_date")  # Date when the item was lost
    item_description = request.form.get("item_description")  # Description of the lost item
    location = request.form.get("location")  # Location where the item was lost
    email = request.form.get("email")  # Email of the claimant
    phone_number = request.form.get("phone")  # Phone number of the claimant
    image_url = request.form.get("image_url")  # Image URL of the lost item

    # Debugging print statement
    print(f"lost_date: {lost_date}, item_description: {item_description}, location: {location}, email: {email}, phone_number: {phone_number}, image_url: {image_url}")

    # Check for required fields
    if not lost_date or not item_description or not location or not email or not phone_number:
        flash("Please fill all required fields.")
        return redirect("/")

    # Inserting into the database
    db.execute("INSERT INTO items (lost_date, item_description, location, email, phone_number, image_url) VALUES (?, ?, ?, ?, ?, ?)",
               lost_date, item_description, location, email, phone_number, image_url)

    flash("Your item has been submitted successfully!")
    return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()  # Clear any existing user session

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not email.endswith("@lsca.edu.ph"):
            flash("Invalid email. Please use your LSCA email.")
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

        if not email or not re.match(r"[^@]+@lsca\.edu\.ph$", email):
            flash("Invalid email format. Please use your LSCA email.")
            return render_template("register.html")

        if not password or len(password) < 8:
            flash("Password must be at least 8 characters long")
            return render_template("register.html")

        if password != confirmation:
            flash("Password and confirmation do not match")
            return render_template("register.html")

        rows = db.execute("SELECT * FROM users WHERE email = ?", email)
        if len(rows) > 0:
            flash("This email is already registered")
            return render_template("register.html")

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
    items = db.execute("SELECT * FROM items")
    return render_template("found-items.html", items=items)

@app.route("/lost")
@login_required
def lost_items():
    """Show all lost items"""
    items = db.execute("SELECT * FROM items")
    return render_template("lost-items.html", items=items)

if __name__ == "__main__":
    app.run(debug=True)
