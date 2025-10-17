from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from functools import wraps
import os
from dotenv import load_dotenv
import json

# Add this after your imports in app.py
def get_locale():
    # Check if language is stored in session
    return session.get('language', 'en')

def get_text(key):
    lang = get_locale()
    file_path = f'locales/{lang}.json'
    
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            translations = json.load(f)
            return translations.get(key, key)
    return key

load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# Mail configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@example.com')

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
csrf = CSRFProtect(app)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Token serializer for password reset and email verification
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    two_fa_secret = db.Column(db.String(32), nullable=True)
    two_fa_enabled = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def generate_2fa_secret(self):
        self.two_fa_secret = pyotp.random_base32()
        return self.two_fa_secret
    
    def get_totp_uri(self):
        return pyotp.totp.TOTP(self.two_fa_secret).provisioning_uri(
            name=self.email,
            issuer_name='Flask Auth App'
        )
    
    def verify_totp(self, token):
        totp = pyotp.TOTP(self.two_fa_secret)
        return totp.verify(token, valid_window=1)

# Create tables
with app.app_context():
    db.create_all()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Email verification required decorator
def email_verified_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = User.query.get(session.get('user_id'))
        if user and not user.email_verified:
            flash('Please verify your email address to access this page.', 'warning')
            return redirect(url_for('unverified'))
        return f(*args, **kwargs)
    return decorated_function

# Add context processor to make get_text available in all templates
@app.context_processor
def utility_processor():
    return dict(get_text=get_text, current_language=get_locale())

# Add language switching route
@app.route('/set-language/<lang>')
def set_language(lang):
    if lang in ['en', 'ar']:
        session['language'] = lang
    return redirect(request.referrer or url_for('index'))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
            return render_template('register.html')
        
        if not email or '@' not in email:
            flash('Please provide a valid email address.', 'error')
            return render_template('register.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html')
        
        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        # Send verification email
        try:
            token = serializer.dumps(email, salt='email-verification-salt')
            verify_url = url_for('verify_email', token=token, _external=True)
            
            msg = Message('Verify Your Email Address',
                        recipients=[email])
            msg.body = f'''Hello {username},

Thank you for registering! Please verify your email address by clicking the link below:

{verify_url}

This link will expire in 24 hours.

If you did not create an account, please ignore this email.

Best regards,
Flask Auth App Team
'''
            mail.send(msg)
            flash('Registration successful! Please check your email to verify your account.', 'success')
        except Exception as e:
            flash('Registration successful! However, we could not send the verification email. Please contact support.', 'warning')
            print(f"Mail error: {e}")
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verification-salt', max_age=86400)  # 24 hours
    except SignatureExpired:
        flash('The verification link has expired. Please request a new one.', 'error')
        return redirect(url_for('resend_verification'))
    except BadSignature:
        flash('The verification link is invalid.', 'error')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first()
    
    if user:
        if user.email_verified:
            flash('Email already verified. Please log in.', 'info')
        else:
            user.email_verified = True
            db.session.commit()
            flash('Your email has been verified successfully! You can now log in.', 'success')
    else:
        flash('User not found.', 'error')
    
    return redirect(url_for('login'))

@app.route('/unverified')
@login_required
def unverified():
    user = User.query.get(session['user_id'])
    if user and user.email_verified:
        return redirect(url_for('dashboard'))
    return render_template('unverified.html')

@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        
        if user:
            if user.email_verified:
                flash('This email is already verified. Please log in.', 'info')
                return redirect(url_for('login'))
            
            try:
                token = serializer.dumps(email, salt='email-verification-salt')
                verify_url = url_for('verify_email', token=token, _external=True)
                
                msg = Message('Verify Your Email Address',
                            recipients=[email])
                msg.body = f'''Hello {user.username},

Please verify your email address by clicking the link below:

{verify_url}

This link will expire in 24 hours.

If you did not create an account, please ignore this email.

Best regards,
Flask Auth App Team
'''
                mail.send(msg)
                flash('Verification email has been sent. Please check your inbox.', 'success')
            except Exception as e:
                flash('Error sending email. Please try again later.', 'error')
                print(f"Mail error: {e}")
        else:
            flash('If that email exists, a verification email has been sent.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('resend_verification.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            if not user.email_verified:
                flash('Please verify your email address before logging in. Check your inbox for the verification link.', 'warning')
                return render_template('login.html')
            
            if user.two_fa_enabled:
                # Store user_id temporarily for 2FA verification
                session['2fa_user_id'] = user.id
                return redirect(url_for('verify_2fa'))
            
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = remember
            
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if '2fa_user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        user = User.query.get(session['2fa_user_id'])
        
        if user and user.verify_totp(token):
            session['user_id'] = user.id
            session['username'] = user.username
            session.pop('2fa_user_id', None)
            
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA code. Please try again.', 'error')
    
    return render_template('verify_2fa.html')

@app.route('/dashboard')
@login_required
@email_verified_required
def dashboard():
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/enable-2fa', methods=['GET', 'POST'])
@login_required
@email_verified_required
def enable_2fa():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        token = request.form.get('token', '').strip()
        
        if user.verify_totp(token):
            user.two_fa_enabled = True
            db.session.commit()
            flash('2FA has been enabled successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid code. Please try again.', 'error')
    
    # Generate 2FA secret if not exists
    if not user.two_fa_secret:
        user.generate_2fa_secret()
        db.session.commit()
    
    # Generate QR code
    qr_uri = user.get_totp_uri()
    qr = qrcode.make(qr_uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    buf.seek(0)
    qr_code_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    
    return render_template('enable_2fa.html', 
                         qr_code=qr_code_base64, 
                         secret=user.two_fa_secret)

@app.route('/disable-2fa', methods=['POST'])
@login_required
@email_verified_required
def disable_2fa():
    user = User.query.get(session['user_id'])
    user.two_fa_enabled = False
    user.two_fa_secret = None
    db.session.commit()
    flash('2FA has been disabled.', 'info')
    return redirect(url_for('dashboard'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        
        if user:
            if not user.email_verified:
                flash('Please verify your email address first.', 'warning')
                return redirect(url_for('resend_verification'))
            
            token = serializer.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Send email
            try:
                msg = Message('Password Reset Request',
                            recipients=[email])
                msg.body = f'''To reset your password, visit the following link:
{reset_url}

This link will expire in 1 hour.

If you did not make this request, please ignore this email.
'''
                mail.send(msg)
                flash('Password reset instructions have been sent to your email.', 'info')
            except Exception as e:
                flash('Error sending email. Please try again later.', 'error')
                print(f"Mail error: {e}")
        else:
            # Don't reveal if email exists
            flash('If that email exists, password reset instructions have been sent.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('reset_password.html', token=token)
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        
        user = User.query.filter_by(email=email).first()
        if user:
            user.set_password(password)
            db.session.commit()
            flash('Your password has been reset successfully!', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)