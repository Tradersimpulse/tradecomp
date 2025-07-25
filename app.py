from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_dance.contrib.google import make_google_blueprint, google
import mysql.connector
from mysql.connector import Error
from datetime import datetime, timedelta
import os
import uuid
import hashlib
import secrets
from dotenv import load_dotenv
import requests
import logging
from werkzeug.security import generate_password_hash, check_password_hash
# REMOVED: from tradelocker import TradeLocker  # This was causing the error

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Google OAuth setup
google_bp = make_google_blueprint(
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    scope=["openid", "email", "profile"]
)
app.register_blueprint(google_bp, url_prefix="/login")

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database configuration
db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'port': int(os.getenv('DB_PORT', 3306))
}

class User(UserMixin):
    def __init__(self, id, username, email, is_admin=False):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = is_admin

def get_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except Error as e:
        logger.error(f"Database connection error: {e}")
        return None

@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_connection()
        if not conn:
            return None
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user_data:
            return User(user_data['id'], user_data['username'], user_data['email'], user_data.get('is_admin', False))
    except Exception as e:
        logger.error(f"Error loading user: {e}")
    return None

def get_competition_dates():
    """Get competition start and end dates from database"""
    try:
        conn = get_connection()
        if not conn:
            return None, None
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT start_date, end_date FROM competition_settings WHERE id = 1")
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if result:
            return result['start_date'], result['end_date']
    except Exception as e:
        logger.error(f"Error getting competition dates: {e}")
    
    return None, None

def calculate_percentage_change(starting_balance, current_balance):
    """Calculate percentage change"""
    if starting_balance == 0:
        return 0
    return ((current_balance - starting_balance) / starting_balance) * 100

def get_leaderboard_data():
    """Get leaderboard data with rankings"""
    try:
        conn = get_connection()
        if not conn:
            return []
        
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT 
            u.username,
            ta.account_id,
            ta.starting_balance,
            ta.current_balance,
            ta.is_active,
            ta.last_updated,
            (ta.current_balance - ta.starting_balance) as profit,
            CASE 
                WHEN ta.starting_balance > 0 
                THEN ((ta.current_balance - ta.starting_balance) / ta.starting_balance) * 100 
                ELSE 0 
            END as percentage_change
        FROM trading_accounts ta
        JOIN users u ON ta.user_id = u.id
        WHERE ta.starting_balance >= 100
        ORDER BY percentage_change DESC
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        
        # Add rank to each result
        for i, result in enumerate(results, 1):
            result['rank'] = i
            result['profit'] = round(result['profit'], 2)
            result['percentage_change'] = round(result['percentage_change'], 2)
        
        return results
    except Exception as e:
        logger.error(f"Error getting leaderboard data: {e}")
        return []

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            conn = get_connection()
            if not conn:
                flash('Database connection error', 'error')
                return render_template('login.html')
            
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user_data = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if user_data and check_password_hash(user_data['password'], password):
                user = User(user_data['id'], user_data['username'], user_data['email'], user_data.get('is_admin', False))
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password', 'error')
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('Login error occurred', 'error')
    
    return render_template('login.html')

@app.route('/auth/google')
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    
    resp = google.get("/oauth2/v1/userinfo")
    if not resp.ok:
        flash('Failed to fetch user info from Google', 'error')
        return redirect(url_for('login'))
    
    google_info = resp.json()
    email = google_info['email']
    name = google_info.get('name', email.split('@')[0])
    
    try:
        conn = get_connection()
        if not conn:
            flash('Database connection error', 'error')
            return redirect(url_for('login'))
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user_data = cursor.fetchone()
        
        if not user_data:
            # Create new user
            cursor.execute("""
                INSERT INTO users (username, email, password, google_id) 
                VALUES (%s, %s, %s, %s)
            """, (name, email, '', google_info['id']))
            user_id = cursor.lastrowid
            conn.commit()
            user = User(user_id, name, email)
        else:
            user = User(user_data['id'], user_data['username'], user_data['email'], user_data.get('is_admin', False))
        
        cursor.close()
        conn.close()
        login_user(user)
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Google auth error: {e}")
        flash('Authentication error occurred', 'error')
        return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('signup.html')
        
        try:
            conn = get_connection()
            if not conn:
                flash('Database connection error', 'error')
                return render_template('signup.html')
            
            cursor = conn.cursor()
            
            # Check if email already exists
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash('Email already registered', 'error')
                cursor.close()
                conn.close()
                return render_template('signup.html')
            
            # Hash password and create user
            hashed_password = generate_password_hash(password)
            cursor.execute("""
                INSERT INTO users (username, email, password) 
                VALUES (%s, %s, %s)
            """, (username, email, hashed_password))
            
            user_id = cursor.lastrowid
            conn.commit()
            cursor.close()
            conn.close()
            
            user = User(user_id, username, email)
            login_user(user)
            flash('Account created successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            logger.error(f"Signup error: {e}")
            flash('Registration error occurred', 'error')
    
    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get user's trading account
        conn = get_connection()
        if not conn:
            flash('Database connection error', 'error')
            return render_template('dashboard.html', has_account=False)
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM trading_accounts WHERE user_id = %s
        """, (current_user.id,))
        account = cursor.fetchone()
        
        # Get leaderboard data to determine user's position
        leaderboard = get_leaderboard_data()
        user_position = None
        top_percentage = None
        
        if account and leaderboard:
            for i, entry in enumerate(leaderboard):
                if entry['account_id'] == account['account_id']:
                    user_position = i + 1
                    break
            
            if leaderboard:
                top_percentage = leaderboard[0]['percentage_change']
        
        # Get competition dates
        start_date, end_date = get_competition_dates()
        
        cursor.close()
        conn.close()
        
        return render_template('dashboard.html', 
                             account=account, 
                             has_account=account is not None,
                             user_position=user_position,
                             top_percentage=top_percentage,
                             start_date=start_date,
                             end_date=end_date)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('dashboard.html', has_account=False)

@app.route('/accounts', methods=['GET', 'POST'])
@login_required
def accounts():
    # Clear any existing TradeLocker session data on page load
    if request.method == 'GET':
        session.pop('tradelocker_accounts', None)
        session.pop('tradelocker_token', None)
        session.pop('tradelocker_env', None)
    
    if request.method == 'POST':
        action = request.form.get('action', 'setup_account')
        
        if action == 'connect_tradelocker':
            return handle_tradelocker_connection()
        elif action == 'add_tradelocker_account':
            return handle_tradelocker_account_selection()
        else:
            return handle_regular_account_setup()
    
    # Get any existing TradeLocker accounts from session
    tradelocker_accounts = session.get('tradelocker_accounts', [])
    
    return render_template('accounts.html', tradelocker_accounts=tradelocker_accounts)

def handle_tradelocker_connection():
    """Handle TradeLocker API connection using direct HTTP requests"""
    try:
        account_type = request.form.get('account_type')  # 'demo' or 'live'
        email = request.form.get('tl_email')
        password = request.form.get('tl_password')
        server = request.form.get('tl_server')
        
        logger.info(f"Attempting TradeLocker connection: {email}, {account_type}, {server}")
        
        # Direct API call for JWT token
        base_url = f"https://{account_type}.tradelocker.com"
        auth_url = f"{base_url}/backend-api/auth/jwt/token"
        
        auth_payload = {
            "email": email,
            "password": password,
            "server": server
        }
        
        # Get JWT token
        response = requests.post(auth_url, json=auth_payload, timeout=30)
        
        # FIX: Accept both 200 and 201 status codes as successful
        if not (200 <= response.status_code < 300):
            flash(f"Authentication failed: {response.status_code} - {response.text}", "error")
            return redirect(url_for('accounts'))
        
        jwt_data = response.json()
        access_token = jwt_data.get('accessToken')
        
        if not access_token:
            flash("Failed to get access token from TradeLocker", "error")
            return redirect(url_for('accounts'))
        
        # Store token in session
        session['tradelocker_token'] = access_token
        session['tradelocker_env'] = account_type
        
        # Calculate token expiry (TradeLocker JWT tokens typically expire in 24 hours)
        try:
            import base64
            import json
            
            # Decode JWT payload (without verification for expiry extraction)
            parts = access_token.split('.')
            if len(parts) >= 2:
                # Add padding if needed for base64 decoding
                payload = parts[1]
                payload += '=' * (4 - len(payload) % 4)
                decoded_payload = base64.b64decode(payload)
                token_data = json.loads(decoded_payload)
                
                # Extract expiry timestamp (exp claim in JWT)
                if 'exp' in token_data:
                    exp_timestamp = token_data['exp']
                    expiry_time = datetime.fromtimestamp(exp_timestamp)
                    session['tradelocker_token_expiry'] = expiry_time.isoformat()
                    logger.info(f"Token expires at: {expiry_time}")
                else:
                    logger.warning("No expiry found in JWT token")
            else:
                logger.warning("Invalid JWT token format")
        except Exception as e:
            logger.warning(f"Could not decode JWT token for expiry: {str(e)}")
            # Fallback to default expiry
            default_expiry = datetime.now() + timedelta(hours=23)
            session['tradelocker_token_expiry'] = default_expiry.isoformat()
        
        # Store login info for later use
        session['tradelocker_login_info'] = {
            'email': email,
            'server': server,
            'env': account_type
        }
        
        # Get all accounts using direct API call
        accounts_url = f"{base_url}/backend-api/trade/accounts"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'accept': 'application/json'
        }
        
        accounts_response = requests.get(accounts_url, headers=headers, timeout=30)
        
        # FIX: Also apply the same fix for accounts API call
        if not (200 <= accounts_response.status_code < 300):
            flash(f"Failed to fetch accounts: {accounts_response.status_code} - {accounts_response.text}", "error")
            return redirect(url_for('accounts'))
        
        accounts_data = accounts_response.json()
        logger.info(f"Accounts API response: {accounts_data}")
        
        # Format accounts for display
        formatted_accounts = []
        accounts_list = accounts_data.get('accounts', [])
        
        for account in accounts_list:
            account_id = account.get('id')
            account_name = account.get('name', '')
            account_balance = account.get('accountBalance', '0.00')
            account_currency = account.get('currency', 'USD')
            account_num = account.get('accNum', '')
            
            if account_id:
                formatted_accounts.append({
                    'id': account_id,
                    'name': account_name,
                    'balance': account_balance,
                    'currency': account_currency,
                    'accNum': account_num,
                    'label': f"{account_name} ({account_currency} {account_balance})"
                })
        
        # Store accounts in session
        session['tradelocker_accounts'] = formatted_accounts
        
        if formatted_accounts:
            flash(f"Successfully found {len(formatted_accounts)} TradeLocker account(s). Please select one below.", "success")
        else:
            flash("No TradeLocker accounts found for this user", "error")
            
        return redirect(url_for('accounts'))
        
    except requests.exceptions.Timeout:
        flash("Connection timeout. Please try again.", "error")
        return redirect(url_for('accounts'))
    except requests.exceptions.RequestException as e:
        flash(f"Connection error: {str(e)}", "error")
        return redirect(url_for('accounts'))
    except Exception as e:
        logger.error(f"TradeLocker connection error: {str(e)}")
        flash(f"Error connecting to TradeLocker: {str(e)}", "error")
        return redirect(url_for('accounts'))

def handle_tradelocker_account_selection():
    """Handle TradeLocker account selection and save to database"""
    try:
        selected_account_id = request.form.get('selected_account')
        tradelocker_accounts = session.get('tradelocker_accounts', [])
        
        if not selected_account_id or not tradelocker_accounts:
            flash("No account selected or session expired", "error")
            return redirect(url_for('accounts'))
        
        # Find the selected account
        selected_account = None
        for account in tradelocker_accounts:
            if account['id'] == selected_account_id:
                selected_account = account
                break
        
        if not selected_account:
            flash("Selected account not found", "error")
            return redirect(url_for('accounts'))
        
        # Save to database
        conn = get_connection()
        if not conn:
            flash('Database connection error', 'error')
            return redirect(url_for('accounts'))
        
        cursor = conn.cursor()
        
        # Delete existing account for this user
        cursor.execute("DELETE FROM trading_accounts WHERE user_id = %s", (current_user.id,))
        
        # Insert new TradeLocker account
        login_info = session.get('tradelocker_login_info', {})
        cursor.execute("""
            INSERT INTO trading_accounts 
            (user_id, account_type, account_id, account_name, starting_balance, current_balance, 
             tl_email, tl_server, account_number, account_env) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            current_user.id, 
            'tradelocker', 
            selected_account['id'],
            selected_account['name'],
            float(selected_account['balance']),
            float(selected_account['balance']),
            login_info.get('email', ''),
            login_info.get('server', ''),
            selected_account['accNum'],
            login_info.get('env', 'demo')
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Clear session data
        session.pop('tradelocker_accounts', None)
        session.pop('tradelocker_token', None)
        session.pop('tradelocker_env', None)
        session.pop('tradelocker_login_info', None)
        
        flash('TradeLocker account added successfully!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"TradeLocker account selection error: {str(e)}")
        flash(f"Error adding TradeLocker account: {str(e)}", "error")
        return redirect(url_for('accounts'))

def handle_regular_account_setup():
    """Handle regular MT5 account setup"""
    try:
        account_type = request.form.get('account_type')
        
        conn = get_connection()
        if not conn:
            flash('Database connection error', 'error')
            return redirect(url_for('accounts'))
        
        cursor = conn.cursor()
        
        # Delete existing account for this user
        cursor.execute("DELETE FROM trading_accounts WHERE user_id = %s", (current_user.id,))
        
        if account_type == 'mt5':
            account_number = request.form.get('mt5_account')
            password = request.form.get('mt5_password')
            server = request.form.get('mt5_server')
            
            cursor.execute("""
                INSERT INTO trading_accounts 
                (user_id, account_type, account_number, mt5_password, mt5_server, starting_balance, current_balance) 
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (current_user.id, account_type, account_number, password, server, 100.0, 100.0))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        flash('Trading account added successfully!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Account setup error: {e}")
        flash('Error setting up account', 'error')
        return redirect(url_for('accounts'))

@app.route('/leaderboard')
def leaderboard():
    leaderboard_data = get_leaderboard_data()
    start_date, end_date = get_competition_dates()
    
    return render_template('leaderboard.html', 
                         leaderboard=leaderboard_data,
                         start_date=start_date,
                         end_date=end_date)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        conn = get_connection()
        if not conn:
            flash('Database connection error', 'error')
            return render_template('admin.html')
        
        cursor = conn.cursor(dictionary=True)
        
        # Get all trading accounts
        cursor.execute("""
            SELECT ta.*, u.username, u.email 
            FROM trading_accounts ta 
            JOIN users u ON ta.user_id = u.id
            ORDER BY ta.created_at DESC
        """)
        accounts = cursor.fetchall()
        
        # Get competition settings
        cursor.execute("SELECT * FROM competition_settings WHERE id = 1")
        settings = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        return render_template('admin.html', accounts=accounts, settings=settings)
    except Exception as e:
        logger.error(f"Admin error: {e}")
        return render_template('admin.html', accounts=[], settings=None)

@app.route('/admin/update_settings', methods=['POST'])
@login_required
def update_admin_settings():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        referral_link = request.form.get('referral_link')
        
        conn = get_connection()
        if not conn:
            flash('Database connection error', 'error')
            return redirect(url_for('admin'))
        
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE competition_settings 
            SET start_date = %s, end_date = %s, referral_link = %s 
            WHERE id = 1
        """, (start_date, end_date, referral_link))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        flash('Settings updated successfully!', 'success')
    except Exception as e:
        logger.error(f"Settings update error: {e}")
        flash('Error updating settings', 'error')
    
    return redirect(url_for('admin'))

@app.route('/api/rules')
def get_rules():
    return jsonify({
        'title': 'HOW TO ENTER TRADING COMPETITION',
        'steps': [
            {
                'step': 1,
                'title': 'Sign up for the broker',
                'description': 'You MUST register an account with the link below to ensure all traders have the same market environments.',
                'link': 'https://plexytrade.com/?t=TBZp1B&term=register'
            },
            {
                'step': 2,
                'title': 'Choose to create Live account',
                'description': 'For Country of Residence, choose OTHER if you reside in the U.S.'
            },
            {
                'step': 3,
                'title': 'Choose either MT5 or Tradelocker',
                'description': 'Select your preferred trading platform'
            },
            {
                'step': 4,
                'title': 'Fund the account',
                'description': 'Fund the account with a MINIMUM of $100'
            },
            {
                'step': 5,
                'title': 'Enter your account info',
                'description': 'Enter your account info on the account page of this website'
            },
            {
                'step': 6,
                'title': 'Start trading!',
                'description': 'The trader with the highest % gain will win'
            }
        ],
        'notes': [
            'You can re-enter with a new account by updating your account info on the accounts page',
            'You can enter with multiple accounts. To do this, you will need to register with a different email address'
        ]
    })

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
