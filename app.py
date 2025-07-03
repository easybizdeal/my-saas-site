# === Core Flask & Extensions ===
from flask import Flask, render_template, redirect, request, url_for, flash, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_dance.contrib.google import make_google_blueprint, google
from itsdangerous import URLSafeTimedSerializer
from flask_migrate import Migrate
import traceback
from flask import request, redirect, url_for, flash
from flask_login import login_required, current_user
import os
import pandas as pd
import chardet

# === Utilities ===
from linkedin_cookie_collector import collect_linkedin_cookies
from werkzeug.utils import secure_filename
from urllib.parse import unquote
from datetime import datetime, timedelta
import pandas as pd
import os, json, shutil
from werkzeug.security import generate_password_hash, check_password_hash

# === Selenium (for LinkedIn Automation) ===
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import time

# ✅ Initialize the Flask app
app = Flask(__name__)
app.secret_key = "your-secret-key"  # ✅ Set secret key here

# ✅ Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'  # Change DB if needed
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ✅ Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.hostinger.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'amit.c@easybizdeal.com'
app.config['MAIL_PASSWORD'] = 'Amit217698$1@'
app.config['MAIL_DEFAULT_SENDER'] = ('Easy Biz Deal', 'amit.c@easybizdeal.com')
mail = Mail(app)

# ✅ Google OAuth Setup
app.config['GOOGLE_OAUTH_CLIENT_ID'] = '...'
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = '...'

google_bp = make_google_blueprint(
    client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
    client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ]
)
app.register_blueprint(google_bp, url_prefix="/login")

# ✅ Login Manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ✅ Token Serializer
serializer = URLSafeTimedSerializer(app.secret_key)

# ✅ Upload Folder
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# === Models ===

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    phone = db.Column(db.String(100))
    state = db.Column(db.String(100))
    city = db.Column(db.String(100))
    company = db.Column(db.String(100))
    job_title = db.Column(db.String(100))
    bio = db.Column(db.Text)
    image = db.Column(db.String(150))
    linkedin_cookie = db.Column(db.String(500))
    linkedin_csrf = db.Column(db.String(500))
    is_verified = db.Column(db.Boolean, default=False)


class ToolActivation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tool_name = db.Column(db.String(150), nullable=False)
    package_name = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    activated_on = db.Column(db.DateTime, default=datetime.utcnow)
    expires_on = db.Column(db.DateTime)


class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    filename = db.Column(db.String(255))
    filepath = db.Column(db.String(255))
    upload_type = db.Column(db.String(50))  # ✅ Add this line
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    folder_name = db.Column(db.String(150))


class UserMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)


class Campaign(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    tool_name = db.Column(db.String(100))
    sub_tool = db.Column(db.String(100))  # ✅ Add this line
    campaign_name = db.Column(db.String(255))
    message_body = db.Column(db.Text)
    upload_file_id = db.Column(db.Integer, db.ForeignKey('uploaded_file.id'))
    daily_limit = db.Column(db.Integer)
    delay_seconds = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# === Login Loader ===

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# === ROUTES ===

# === HOMEPAGE ===
@app.route('/')
def homepage():
    return render_template('homepage.html')

# === SIGN UP ===
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        country = request.form['country']
        email = request.form['email'].strip().lower()
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists.", "danger")
            return redirect(url_for('signup'))

        user = User(
            first_name=first_name,
            last_name=last_name,
            country=country,
            email=email,
            password=hashed_password,
            is_verified=False
        )

        try:
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print("SIGNUP ERROR:", e)
            flash("Something went wrong during signup.", "danger")
            return redirect(url_for('signup'))

        login_user(user)
        session['show_verify_popup'] = True  # ✅ trigger popup on dashboard

        token = serializer.dumps(email, salt='email-confirm')
        verify_link = url_for('verify_email', token=token, _external=True)
        send_verification_email(email, first_name, verify_link)

        print("Signup successful for:", email)
        flash("Account created! Please check your email to verify.", "success")
        return redirect(url_for('dashboard'))

    return render_template('signup.html')


# === VERIFY EMAIL ROUTE ===
@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except Exception as e:
        flash("Verification link is invalid or expired.", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user and not user.is_verified:
        user.is_verified = True
        db.session.commit()
        session['show_verified_popup'] = True  # ✅ trigger success popup
        flash("Email verified successfully!", "success")
    elif not user:
        flash("User not found.", "danger")

    return redirect(url_for('dashboard'))

# === LOGIN ===
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("No account found with this email.", "danger")
            return redirect('/login')

        if not user.is_verified:
            flash("Please verify your email before logging in.", "warning")
            return redirect('/login')

        if not check_password_hash(user.password, password):
            flash("Incorrect password.", "danger")
            return redirect('/login')

        login_user(user)
        flash("Welcome back!", "success")
        return redirect('/dashboard')

    return render_template('login.html')

# === Create Tables on First Run ===
with app.app_context():
    db.create_all()

# === LOGOUT ===
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You've been logged out.", "info")
    return redirect('/login')

@app.route('/hire', methods=['GET', 'POST'])
def hire_freelancer():
    if request.method == 'POST':
        file = request.files.get('file')
        filename = ""
        if file and file.filename:
            filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        data = {
            'country': request.form.get('country'),
            'name': request.form.get('name'),
            'email': request.form.get('email'),
            'role': request.form.get('role'),
            'title': request.form.get('title'),
            'description': request.form.get('description'),
            'timeframe': request.form.get('timeframe'),
            'has_account': request.form.get('has_account'),
            'communication': request.form.get('communication'),
            'submitted_at': datetime.now().strftime("%Y-%m-%d %H:%M"),
            'filename': filename
        }

        print("SUBMISSION RECEIVED:", data)  # Optional debug log
        inquiries.append(data)

        # Redirect based on communication method
        if data['communication'] == "WhatsApp":
            return redirect("https://wa.me/8801717085981")
        elif data['communication'] == "Email":
            message = "Thanks! Our team will email you within the next hour."
        else:
            message = "Thanks! Our team will contact you via email to schedule your virtual meeting."

        return render_template('thank_you.html', message=message)

    return render_template('hire_freelancer.html')

@app.route('/thank-you')
def thank_you():
    return render_template('thank_you.html')

@app.route('/admin/inquiries')
def admin_inquiries():
    return render_template('admin_inquiries.html', inquiries=inquiries)


# === TERMS PAGE ===
@app.route('/terms')
def terms():
    return render_template('terms.html')

# === GOOGLE LOGIN ===
@app.route('/google-login')
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Google login failed.", "danger")
        return redirect("/login")

    user_info = resp.json()
    email = user_info["email"]
    first_name = user_info.get("given_name", "")
    last_name = user_info.get("family_name", "")

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            country="Unknown",  # Default since country is required
            password="",         # No password needed for OAuth
            is_verified=True     # Automatically verified
        )
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash("Logged in via Google successfully!", "success")
    return redirect("/dashboard")


# === FORGOT PASSWORD ===
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("No user found with this email.", "danger")
            return redirect('/forgot-password')

        token = serializer.dumps(email, salt='password-reset')
        reset_link = url_for('reset_password', token=token, _external=True)
        send_reset_email(email, user.first_name, reset_link)

        flash("Check your email for the password reset link.", "info")
        return redirect('/login')

    return render_template('forgot_password.html')


# === RESET PASSWORD ===
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
    except:
        flash("Reset link is invalid or expired.", "danger")
        return redirect('/forgot-password')

    user = User.query.filter_by(email=email).first_or_404()

    if request.method == 'POST':
        new_password = request.form['password']
        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash("Password updated! Please log in.", "success")
        return redirect('/login')

    return render_template('reset_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_campaigns = Campaign.query.filter_by(user_id=current_user.id).all()
    user_files = UploadedFile.query.filter_by(user_id=current_user.id).all()

    show_verify_popup = session.pop('show_verify_popup', False)
    show_verified_popup = session.pop('show_verified_popup', False)

    return render_template(
        'dashboard.html',
        campaigns=user_campaigns,
        files=user_files,
        show_verify_popup=show_verify_popup,
        show_verified_popup=show_verified_popup
    )
    
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        user = current_user
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.country = request.form['country']
        user.phone = request.form.get('phone')
        user.state = request.form.get('state')
        user.city = request.form.get('city')
        user.company = request.form.get('company')
        user.job_title = request.form.get('job_title')
        user.bio = request.form.get('bio')

        image = request.files.get('profile_image')
        if image and image.filename != '':
            filename = secure_filename(image.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(filepath)
            user.image = filename

        db.session.commit()
        flash("Profile updated successfully.")
        return redirect(url_for('profile'))

    return render_template('profile.html')

# Makes request path available in all templates
@app.context_processor
def inject_request_path():
    return dict(current_path=request.path)

# all my-crm route
@app.route('/my-crm')
@login_required
def my_crm():
    return render_template('crm/my_crm.html')

# LinkedIn Campaign all templates
@app.route('/campaign_home')
@login_required
def campaign_home():
    return render_template('campaign_home.html')

# LinkedIn Campaign Dashboard
@app.route('/campaigns/linkedin')
@login_required
def linkedin_campaign():
    campaigns = Campaign.query.filter_by(user_id=current_user.id, tool_name='linkedin').all()
    return render_template('campaigns/linkedin.html', campaigns=campaigns)

# Edit Campaign
@app.route('/campaigns/edit/<int:campaign_id>')
@login_required
def edit_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    if campaign.user_id != current_user.id:
        flash('Unauthorized', 'danger')
        return redirect(url_for('linkedin_campaign'))
    return render_template('campaigns/edit_campaign.html', campaign=campaign)

@app.route('/campaigns/delete/<int:campaign_id>', methods=['POST'])
@login_required
def delete_campaign(campaign_id):
    campaign = Campaign.query.filter_by(id=campaign_id, user_id=current_user.id).first()
    if campaign:
        db.session.delete(campaign)
        db.session.commit()
    return redirect(url_for('linkedin_campaign'))

@app.route('/campaigns/linkedin/create', methods=['GET', 'POST'])
@login_required
def create_linkedin_campaign():
    if request.method == 'POST':
        campaign_name = request.form.get('campaign_name')
        message_template = request.form.get('message_template')
        uploaded_file = request.files.get('file_upload')
        daily_limit = request.form.get('daily_limit')

        if not uploaded_file or uploaded_file.filename == '':
            flash("Please upload a file to continue.", "danger")
            return redirect(request.url)

        # Save uploaded file
        filename = secure_filename(uploaded_file.filename)
        folder_path = f'static/uploads/{current_user.id}/crm/linkedin_campaigns'
        os.makedirs(folder_path, exist_ok=True)
        filepath = os.path.join(folder_path, filename)
        uploaded_file.save(filepath)

        # Save to UploadedFile table
        file_record = UploadedFile(
            user_id=current_user.id,
            filename=filename,
            filepath=filepath,
            folder_name='linkedin_campaigns',
            upload_type='linkedin_campaign'
        )
        db.session.add(file_record)
        db.session.commit()

        # Create campaign entry
        new_campaign = Campaign(
            user_id=current_user.id,
            tool_name='linkedin',
            sub_tool='auto_messaging',
            campaign_name=campaign_name,
            message_body=message_template,
            upload_file_id=file_record.id,
            daily_limit=int(daily_limit or 50),
            delay_seconds=30
        )
        db.session.add(new_campaign)
        db.session.commit()

        flash("Campaign created successfully!", "success")
        return redirect(url_for('linkedin_campaign'))
    return render_template("campaigns/create_campaign.html")

# Route: Silent LinkedIn Login via ChromeDriver (automated cookie capture)
@app.route('/linkedin-login-silent')
@login_required
def linkedin_login_silent():
    campaign_id = request.args.get('campaign_id')

    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from webdriver_manager.chrome import ChromeDriverManager
        import time

        # Set up Chrome options
        options = Options()
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--start-maximized")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)
        options.add_experimental_option("detach", True)

        # Start Chrome driver
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        driver.get("https://www.linkedin.com/login")

        # Wait for login to complete
        time.sleep(40)

        # Collect cookies
        cookies = driver.get_cookies()
        li_at = next((cookie['value'] for cookie in cookies if cookie['name'] == 'li_at'), None)
        jsessionid = next((cookie['value'] for cookie in cookies if cookie['name'] == 'JSESSIONID'), None)

        driver.quit()

        li_at = None
        jsessionid = None
        for cookie in cookies:
            if cookie['name'] == 'li_at':
                li_at = cookie['value']
            elif cookie['name'] == 'JSESSIONID':
                jsessionid = cookie['value']

        if li_at and jsessionid:
            current_user.linkedin_cookie = li_at
            current_user.linkedin_csrf = jsessionid
            db.session.commit()

            flash("✅ LinkedIn connected successfully!", "success")
        else:
            current_user.linkedin_cookie = None
            current_user.linkedin_csrf = None
            db.session.commit()

            flash("❌ Failed to capture LinkedIn session cookies. Try again.", "danger")

        return redirect(url_for('linkedin_campaign'))

    except Exception as e:
        flash(f"⚠️ LinkedIn login error: {str(e)}", "danger")
        return redirect(url_for('linkedin_campaign'))

@app.route("/linkedin-disconnect")
@login_required
def linkedin_disconnect():
    current_user.linkedin_cookie = None
    current_user.linkedin_csrf = None
    db.session.commit()
    flash("You have been disconnected from LinkedIn.", "info")
    return redirect(url_for('linkedin_campaign'))  # or another valid fallback

@app.route('/campaign/<int:campaign_id>/send-test', methods=['POST'])
@login_required
def send_test_message(campaign_id):
    try:
        campaign = Campaign.query.get_or_404(campaign_id)

        if not current_user.linkedin_cookie or not current_user.linkedin_csrf:
            flash("❌ Please connect LinkedIn first.", "warning")
            return redirect(url_for('linkedin_campaign'))

        uploaded_file = UploadedFile.query.get(campaign.upload_file_id)
        file_path = os.path.join("static", "uploads", str(current_user.id), "crm", uploaded_file.folder_name, uploaded_file.filename)

        if not os.path.exists(file_path):
            flash("❌ Uploaded file not found.", "danger")
            return redirect(url_for('linkedin_campaign'))

        # Load file
        if file_path.endswith('.csv'):
            with open(file_path, 'rb') as f:
                result = chardet.detect(f.read())
            encoding = result['encoding']
            try:
                df = pd.read_csv(file_path, encoding=encoding)
            except Exception:
                df = pd.read_csv(file_path, encoding='ISO-8859-1')
        elif file_path.endswith('.xlsx'):
            df = pd.read_excel(file_path)
        else:
            flash("❌ Unsupported file format.", "danger")
            return redirect(url_for('linkedin_campaign'))

        if df.empty:
            flash("❌ File has no contacts.", "warning")
            return redirect(url_for('linkedin_campaign'))

        # Use second row if first is header
        first_row = df.iloc[0] if df.iloc[0].get("LinkedIn") else df.iloc[1]
        linkedin_url = first_row.get("LinkedIn")
        if not linkedin_url:
            flash("❌ LinkedIn URL is missing in the contact row.", "danger")
            return redirect(url_for('linkedin_campaign'))

        # Message replacement
        message = campaign.message_body
        replacements = {
            "{{First Name}}": first_row.get("First Name", ""),
            "{{Company Name}}": first_row.get("Company Name", ""),
            "{{Title}}": first_row.get("Title", "")
        }
        for tag, val in replacements.items():
            message = message.replace(tag, str(val))

        # Start Selenium
        chrome_options = Options()
        chrome_options.add_argument("--headless=new")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--window-size=1920,1080")

        driver = webdriver.Chrome(options=chrome_options)

        try:
            # LinkedIn session setup
            driver.get("https://www.linkedin.com")
            time.sleep(3)
            driver.delete_all_cookies()
            driver.add_cookie({'name': 'li_at', 'value': current_user.linkedin_cookie, 'domain': '.linkedin.com'})
            driver.add_cookie({'name': 'JSESSIONID', 'value': current_user.linkedin_csrf, 'domain': '.www.linkedin.com'})
            driver.get(linkedin_url)

            WebDriverWait(driver, 15).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))
            time.sleep(3)

            # Locate and click the "Message" button
            try:
                msg_btn = WebDriverWait(driver, 15).until(
                    EC.presence_of_element_located((By.XPATH, '//span[text()="Message"]/ancestor::button'))
                )
                driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", msg_btn)
                time.sleep(1)
                driver.execute_script("arguments[0].click();", msg_btn)
                time.sleep(3)
            except TimeoutException:
                raise Exception("❌ 'Message' button not found or not clickable. Make sure the user is a connection.")

            # Locate the message input box
            input_box = WebDriverWait(driver, 15).until(
                EC.visibility_of_element_located((By.XPATH, '//div[@role="textbox" and contains(@aria-label, "Write a message")]'))
            )
            driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", input_box)
            driver.execute_script("arguments[0].click();", input_box)
            input_box.send_keys(message)
            time.sleep(2)

            # Click send button
            send_btn = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.XPATH, '//button[contains(@class, "msg-form__send-button")]'))
            )
            send_btn.click()

            flash("✅ Test message sent to first contact!", "success")

        except Exception as e:
            print("❌ Selenium error:")
            traceback.print_exc()
            flash(f"⚠️ Couldn't send message via LinkedIn: {type(e).__name__} - {str(e)}", "danger")

        finally:
            driver.quit()

        return redirect(url_for('linkedin_campaign'))

    except Exception as e:
        traceback.print_exc()
        flash(f"❌ Error in Send Test: {str(e)}", "danger")
        return redirect(url_for('linkedin_campaign'))

# ✅ App Run
if __name__ == '__main__':
    import socket
    try:
        app.run(debug=True, use_reloader=False)
    except socket.error as e:
        print("Socket error on restart:", e)