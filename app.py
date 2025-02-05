from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
from flask_mail import Mail, Message
import os
import re
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import time
from functools import lru_cache
import requests.exceptions

load_dotenv()

# Configure application
app = Flask(__name__)

# Add security configurations
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT', 'your-security-salt-here')

# Ensure templates auto-reload
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_USER')

mail = Mail(app)

# Configure session to use filesystem
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
    if session.pop("reset_email_sent", False):
        flash("Password reset instructions have been sent to your email. Please check your email.")
    try:
        user_email = db.execute("SELECT email FROM users WHERE id = ?", session["user_id"])[0]["email"]
        
        if user_email == "ritchangelo.dacanay@lsca.edu.ph":
            items = db.execute("SELECT * FROM items")
            return render_template("admin-dashboard.html", items=items)
        else:
            return render_template("submission.html")
    
    except Exception as e:
        print(f"Error fetching items: {e}")
        return render_template("admin-dashboard.html", items=[])
    



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    session.clear()

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not email.endswith("@lsca.edu.ph"):
            flash("Invalid email. Please use your LSCA email.")
            return render_template("login.html")

        try:
            rows = db.execute("SELECT * FROM users WHERE email = ?", email)
        except Exception as e:
            flash("An error occurred while checking your credentials.")
            print(f"Error fetching user: {e}")
            return render_template("login.html")

        if not rows:
            flash("No account found with that email address. Please register first.")
            return redirect(url_for('register'))

        if not password:
            flash("Please provide a password")
            return render_template("login.html")

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

        try:
            # Check if email already exists
            rows = db.execute("SELECT * FROM users WHERE email = ?", email)
            
            if rows and len(rows) > 0:
                flash("This email is already registered")
                return render_template("register.html")

            # Hash password and insert new user
            hashed_password = generate_password_hash(password)
            user_id = db.execute(
                "INSERT INTO users (email, hash, is_confirmed) VALUES (?, ?, FALSE)", 
                email, hashed_password
            )
            
            # Log the user in and send confirmation email
            session["user_id"] = user_id
            send_confirmation_email(email)
            
            flash("Registration successful! Please check your email to confirm your account.")
            return redirect(url_for('unconfirmed'))
            
        except Exception as e:
            print(f"Error during registration: {e}")
            flash("An error occurred during registration")
            return render_template("register.html")

    return render_template("register.html")

@app.route("/submit", methods=["POST"])
@login_required
def submit_item():
    """Submit a lost or found item"""
    item_status = request.form.get("item_status")
    date = request.form.get("date")
    item_description = request.form.get("item_description")
    location = request.form.get("location")
    email = request.form.get("email")
    grade_and_section = request.form.get("grade_and_section")
    phone_number = request.form.get("phone_number")
    image_url = request.form.get("image_url")

    if not all([item_status, date, item_description, location, email, grade_and_section, phone_number]):
        flash("Please fill in all required fields.")
        return redirect("/")

    lost_date = date if item_status == "Lost" else None
    found_date = date if item_status == "Found" else None

    try:
        db.execute(
            "INSERT INTO items (item_status, lost_date, found_date, item_description, location, email, grade_and_section, phone_number, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            item_status, lost_date, found_date, item_description, location, email, grade_and_section, phone_number, image_url
        )
    except Exception as e:
        flash("An error occurred while submitting your item.")
        print(f"Error inserting item: {e}")
        return redirect("/")

    flash("Your item has been submitted successfully!")
    return redirect("/")

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
        data = request.json
        valid_fields = ["item_status", "lost_date", "found_date", "item_description", 
                       "location", "found_location", "email", "grade_and_section", 
                       "phone_number", "image_url"]

        for entry in data['data']:
            id = entry['id']
            field = entry['field']
            value = entry['value']

            if field not in valid_fields:
                return jsonify({'success': False, 'error': f"Invalid field: {field}"})

            query = f"UPDATE items SET {field} = ? WHERE id = ?"
            db.execute(query, value, id)

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

        db.execute("UPDATE items SET item_status = ? WHERE id = ?", item_status, item_id)
        return jsonify({'success': True})
    
    except Exception as e:
        print(f"Error updating status: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        
        if not email or not email.endswith("@lsca.edu.ph"):
            flash("Invalid email. Please use your LSCA email.")
            return render_template("forgot-password.html")
            
        user = db.execute("SELECT * FROM users WHERE email = ?", email)
        if not user:
            flash("No account found with that email address.")
            return render_template("forgot-password.html")
            
        try:
            token = generate_token(email)
            reset_url = url_for('reset_password', token=token, _external=True)
            
            html = render_template('reset_password_email.html', reset_url=reset_url)
            subject = "Password Reset Request"
            msg = Message(
                subject,
                recipients=[email],
                html=html,
                sender=app.config['MAIL_DEFAULT_SENDER']
            )
            
            mail.send(msg)
            flash("Password reset instructions have been sent to your email. Please check your email.")
            return render_template("forgot-password.html")
            
        except Exception as e:
            print(f"Error sending email: {e}")
            flash("Error sending reset email. Please try again later.")
            return render_template("forgot-password.html")
            
    return render_template("forgot-password.html")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = confirm_token(token)
        if not email:
            flash('The password reset link is invalid or has expired.', 'danger')
            return redirect(url_for('login'))
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
        
    if request.method == "POST":
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        
        if not password or len(password) < 8:
            flash("Password must be at least 8 characters long")
            return render_template("reset-password.html")
            
        if password != confirmation:
            flash("Password and confirmation do not match")
            return render_template("reset-password.html")
            
        try:
            hashed_password = generate_password_hash(password)
            db.execute("UPDATE users SET hash = ? WHERE email = ?", hashed_password, email)
            flash("Your password has been updated. Please login with your new password.")
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error resetting password: {e}")
            flash("An error occurred. Please try again later.")
            return render_template("reset-password.html")
            
    return render_template("reset-password.html")
def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
        return email
    except:
        return False

def send_confirmation_email(user_email):
    token = generate_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('confirm_email.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    
    msg = Message(
        subject,
        recipients=[user_email],
        html=html,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)

@app.route('/confirm/<token>')
@login_required
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('index'))
    
    user_id = session["user_id"]
    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)[0]
    
    if user["is_confirmed"]:
        flash('Account already confirmed.', 'success')
    else:
        db.execute(
            "UPDATE users SET is_confirmed = TRUE, confirmed_on = ? WHERE id = ?",
            datetime.now(), user_id
        )
        flash('You have confirmed your account. Thanks!', 'success')
    
    return redirect(url_for('index'))

@app.route('/resend')
@login_required
def resend_confirmation():
    user_id = session["user_id"]
    user = db.execute("SELECT * FROM users WHERE id = ?", user_id)[0]
    
    if user["is_confirmed"]:
        flash('Your account is already confirmed.', 'success')
        return redirect(url_for('index'))
    
    send_confirmation_email(user["email"])
    flash('A new confirmation email has been sent.', 'success')
    return redirect(url_for('index'))

def check_confirmed(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if user_id:
            user = db.execute("SELECT is_confirmed FROM users WHERE id = ?", user_id)[0]
            if not user["is_confirmed"]:
                flash('Please confirm your account!', 'warning')
                return redirect(url_for('unconfirmed'))
        return func(*args, **kwargs)
    return decorated_function

@app.route('/unconfirmed')
@login_required
def unconfirmed():
    user_id = session.get("user_id")
    if user_id:
        user = db.execute("SELECT is_confirmed FROM users WHERE id = ?", user_id)[0]
        if user["is_confirmed"]:
            return redirect(url_for('index'))
    return render_template('unconfirmed.html')

# Initialize model with longer timeout and retries
@lru_cache(maxsize=1)
def get_model():
    max_retries = 3
    base_delay = 1
    
    for attempt in range(max_retries):
        try:
            # Remove "timeout" parameter
            return SentenceTransformer(
                'all-MiniLM-L6-v2',
                device='cpu',
                cache_folder='./model_cache'
            )
        except requests.exceptions.ReadTimeout as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(base_delay * (2 ** attempt))

# Initialize model lazily
model = None

@app.route("/find-similar-items", methods=["POST"])
@login_required
def find_similar_items():
    global model
    
    try:
        # Initialize model on first request
        if model is None:
            try:
                model = get_model()
            except Exception as e:
                print(f"Error loading model: {e}")
                return jsonify({
                    'success': False, 
                    'error': 'Model initialization failed. Please try again later.'
                })

        data = request.json
        description = data.get("description")
        
        if not description:
            return jsonify({
                'success': False,
                'error': 'No description provided'
            })

        # Get all found items
        found_items = db.execute("SELECT * FROM items WHERE item_status = 'Found'")
        
        if not found_items:
            return jsonify({'success': True, 'items': []})
        
        # Create embeddings
        query_embedding = model.encode([description])[0]
        found_descriptions = [item['item_description'] for item in found_items]
        found_embeddings = model.encode(found_descriptions)
        
        # Calculate similarities
        similarities = cosine_similarity([query_embedding], found_embeddings)[0]
        
        # Sort items by similarity
        similar_items = []
        for idx, similarity in enumerate(similarities):
            if similarity > 0.3:  # Similarity threshold
                item = found_items[idx]
                item['similarity'] = float(similarity)
                similar_items.append(item)
        
        # Sort by similarity score
        similar_items.sort(key=lambda x: x['similarity'], reverse=True)
        
        return jsonify({'success': True, 'items': similar_items[:5]})  # Return top 5 matches
        
    except Exception as e:
        print(f"Error finding similar items: {e}")
        return jsonify({'success': False, 'error': str(e)})

if __name__ == "__main__":
    # Pre-load model before running server
    try:
        print("Loading model...")
        model = get_model()
        print("Model loaded successfully")
    except Exception as e:
        print(f"Warning: Model failed to load: {e}")
        print("Model will be loaded on first request")
    
    app.run(host='0.0.0.0', port=5001, debug=True)