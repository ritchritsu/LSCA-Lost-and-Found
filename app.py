import re
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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
@app.route("/mark-found/<int:item_id>", methods=["POST"])
@login_required
def mark_found(item_id):
    """Mark item as found and send email notification"""
    try:
        # Fetch the item details from the database
        item = db.execute("SELECT * FROM items WHERE id = ?", item_id)
        if not item:
            return jsonify({'success': False, 'error': 'Item not found'})

        item = item[0]

        # Update the item status to 'found'
        db.execute("UPDATE items SET item_status = ?, found_date = ? WHERE id = ?",
                   'found', str(datetime.date.today()), item_id)

        # Send email notification
        send_email(item['email'], item['item_description'])

        return jsonify({'success': True})

    except Exception as e:
        print(f"Error marking item as found: {e}")
        return jsonify({'success': False, 'error': str(e)})

def send_email(recipient_email, item_description):
    """Send email to the person who reported the item as lost"""
    sender_email = "your_email@example.com"
    password = "your_email_password"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = "Item Found - Notification"

    body = f"Dear Student,\n\nYour item '{item_description}' has been marked as found.\n\nThank you."
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Set up the SMTP server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Error sending email: {e}")
        
@app.route("/")
@login_required
def index():
    """Show submission form or admin dashboard based on user"""
    try:
        # Fetch the current user's email from the session
        user_email = db.execute("SELECT email FROM users WHERE id = ?", session["user_id"])[0]["email"]
        
        # Check if the user is the specific admin
        if user_email == "ritchangelo.dacanay@lsca.edu.ph":
            # Fetch all items for the admin dashboard
            items = db.execute("SELECT * FROM items")
            return render_template("admin-dashboard.html", items=items)
        else:
            # Redirect non-admin users to the submission page
            return render_template("submission.html")
    
    except Exception as e:
        print(f"Error fetching items: {e}")
        return render_template("admin-dashboard.html", items=[])

@app.route("/submit", methods=["POST"])
@login_required
def submit_item():
    """Submit a lost or found item"""
    # Get form data
    item_status = request.form.get("item_status")
    date = request.form.get("date")
    item_description = request.form.get("item_description")
    location = request.form.get("location")
    email = request.form.get("email")
    grade_and_section = request.form.get("grade_and_section")
    phone_number = request.form.get("phone_number")
    image_url = request.form.get("image_url")

    # Check for required fields
    if not all([item_status, date, item_description, location, email, grade_and_section, phone_number]):
        flash("Please fill in all required fields.")
        return redirect("/")

    # Determine the correct date and location fields based on item_status
    lost_date = date if item_status == "lost" else ""
    found_date = date if item_status == "found" else ""
    lost_location = location if item_status == "lost" else ""
    found_location = location if item_status == "found" else ""

    # Insert data into the database
    try:
        db.execute(
            "INSERT INTO items (item_status, lost_date, found_date, item_description, location, found_location, email, grade_and_section, phone_number, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            item_status, lost_date, found_date, item_description, lost_location, found_location, email, grade_and_section, phone_number, image_url
        )
    except Exception as e:
        flash("An error occurred while submitting your item.")
        print(f"Error inserting item: {e}")
        return redirect("/")

    flash("Your item has been submitted successfully!")
    return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()  # Clear any existing user session

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Validate email format
        if not email or not email.endswith("@lsca.edu.ph"):
            flash("Invalid email. Please use your LSCA email.")
            return render_template("login.html")

        try:
            rows = db.execute("SELECT * FROM users WHERE email = ?", email)
        except Exception as e:
            flash("An error occurred while checking your credentials.")
            print(f"Error fetching user: {e}")
            return render_template("login.html")

        # Validate password
        if not password:
            flash("Please provide a password")
            return render_template("login.html")

        # Check user credentials
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

        # Validate email format
        if not email or not re.match(r"[^@]+@lsca\.edu\.ph$", email):
            flash("Invalid email format. Please use your LSCA email.")
            return render_template("register.html")

        # Validate password
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

        # Hash password and insert new user into database
        hashed_password = generate_password_hash(password)

        try:
            db.execute("INSERT INTO users (email, hash) VALUES (?, ?)", email, hashed_password)
            flash("Registration successful!")
            return redirect("/login")
        except Exception as e:
            print(f"Error during registration: {e}")
            flash("An error occurred during registration")
            return render_template("register.html")

    return render_template("register.html")

@app.route("/found")
@login_required
def found_items():
    """Show all found items"""
    items = db.execute("SELECT * FROM items WHERE item_status = 'found'")
    return render_template("found-items.html", items=items)

@app.route("/lost")
@login_required
def lost_items():
    """Show all lost items"""
    items = db.execute("SELECT * FROM items WHERE item_status = 'lost'")
    return render_template("lost-items.html", items=items)

@app.route("/update-table-data", methods=["POST"])
@login_required
def update_table_data():
    """Update the table data in the database"""
    try:
        # Access the data sent in the request
        data = request.json  # request.json should contain [{id, field, value}, ...]
        
        # List of valid field names to prevent SQL injection
        valid_fields = ["item_status", "lost_date", "found_date", "item_description", 
                        "location", "found_location", "email", "grade_and_section", 
                        "phone_number", "image_url"]

        for entry in data['data']:
            id = entry['id']
            field = entry['field']
            value = entry['value']

            # Check if the field is valid
            if field not in valid_fields:
                return jsonify({'success': False, 'error': f"Invalid field: {field}"})
            
            # Debugging: Print the data before running the query
            print(f"Updating record with ID: {id}, Field: {field}, Value: {value}")

            # Construct the query dynamically
            query = f"UPDATE items SET {field} = ? WHERE id = ?"

            # Execute the query with the correct parameters (value, id)
            db.execute(query, (value, id))  # This is correct: a tuple of two values

        return jsonify({'success': True})
    
    except Exception as e:
        print(f"Error updating data: {e}")
        return jsonify({'success': False, 'error': str(e)})
    
@app.route("/update-status", methods=["POST"])
@login_required
def update_status():
    """Update the item status in the database"""
    try:
        data = request.json
        item_id = data.get("id")
        item_status = data.get("item_status")

        if not item_id or not item_status:
            return jsonify({'success': False, 'error': 'Invalid request'})

        # Update the item status in the database
        db.execute("UPDATE items SET item_status = ? WHERE id = ?", item_status, item_id)

        return jsonify({'success': True})
    
    except Exception as e:
        print(f"Error updating status: {e}")
        return jsonify({'success': False, 'error': str(e)})



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001, debug=True)