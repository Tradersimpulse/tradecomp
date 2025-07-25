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

# Updated User class with multi-account support
class User(UserMixin):
    def __init__(self, id, username, email, is_admin=False):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = is_admin
        self._accounts = None
        self._current_account_id = None
    
    @property
    def accounts(self):
        """Get list of account IDs for this user"""
        if self._accounts is None:
            try:
                conn = get_connection()
                if conn:
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT account_id FROM trading_accounts WHERE user_id = %s", (self.id,))
                    results = cursor.fetchall()
                    self._accounts = [result['account_id'] for result in results]
                    cursor.close()
                    conn.close()
                else:
                    self._accounts = []
            except Exception as e:
                logger.error(f"Error getting user accounts: {e}")
                self._accounts = []
        return self._accounts
    
    @property
    def current_account_id(self):
        """Get the current active account ID"""
        if self._current_account_id is None:
            try:
                conn = get_connection()
                if conn:
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("""
                        SELECT account_id FROM trading_accounts 
                        WHERE user_id = %s AND is_active = 1 
                        ORDER BY created_at DESC LIMIT 1
                    """, (self.id,))
                    result = cursor.fetchone()
                    self._current_account_id = result['account_id'] if result else None
                    cursor.close()
                    conn.close()
            except Exception as e:
                logger.error(f"Error getting current account: {e}")
                self._current_account_id = None
        return self._current_account_id

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

# Updated dashboard with multi-account support
@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get user's trading accounts
        user_accounts = current_user.accounts
        current_account_id = current_user.current_account_id
        
        # Get detailed account info if user has accounts
        account_details = None
        if user_accounts:
            conn = get_connection()
            if conn:
                cursor = conn.cursor(dictionary=True)
                
                # Get current active account details
                if current_account_id:
                    cursor.execute("""
                        SELECT * FROM trading_accounts 
                        WHERE user_id = %s AND account_id = %s
                    """, (current_user.id, current_account_id))
                    account_details = cursor.fetchone()
                
                # If no active account, get the first one
                if not account_details and user_accounts:
                    cursor.execute("""
                        SELECT * FROM trading_accounts 
                        WHERE user_id = %s AND account_id = %s
                    """, (current_user.id, user_accounts[0]))
                    account_details = cursor.fetchone()
                
                cursor.close()
                conn.close()
        
        # Get leaderboard data for position calculation
        leaderboard = get_leaderboard_data()
        user_position = None
        top_percentage = None
        
        if account_details and leaderboard:
            account_identifier = account_details.get('account_id')
            for i, entry in enumerate(leaderboard):
                if entry.get('account_id') == account_identifier:
                    user_position = i + 1
                    break
            
            if leaderboard:
                top_percentage = leaderboard[0]['percentage_change']
        
        # Get competition dates
        start_date, end_date = get_competition_dates()
        
        return render_template('dashboard.html', 
                             account=account_details,
                             has_account=len(user_accounts) > 0,
                             user_accounts=user_accounts,
                             current_account_id=current_account_id,
                             user_position=user_position,
                             top_percentage=top_percentage,
                             start_date=start_date,
                             end_date=end_date)
                             
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('dashboard.html', 
                             has_account=False, 
                             account=None,
                             user_accounts=[])

@app.route('/accounts', methods=['GET', 'POST'])
@login_required
def accounts():
    if request.method == 'GET':
        # DON'T clear session data on page load - let it persist for account selection
        # Only clear if there's a specific clear parameter
        if request.args.get('clear') == 'true':
            session.pop('tradelocker_accounts', None)
            session.pop('tradelocker_token', None)
            session.pop('tradelocker_env', None)
            session.pop('tradelocker_login_info', None)
        
        # Get any existing TradeLocker accounts from session
        tradelocker_accounts = session.get('tradelocker_accounts', [])
        
        return render_template('accounts.html', 
                             tradelocker_accounts=tradelocker_accounts,
                             success_message=session.pop('success_message', None),
                             error_message=session.pop('error_message', None))
    
    if request.method == 'POST':
        action = request.form.get('action', 'setup_account')
        
        if action == 'connect_tradelocker':
            return handle_tradelocker_connection()
        elif action == 'add_tradelocker_accounts':
            return handle_tradelocker_accounts_addition()
        else:
            return handle_regular_account_setup()

def handle_tradelocker_connection():
    """Handle TradeLocker API connection - fetch accounts for selection"""
    try:
        account_type = request.form.get('account_type', 'demo')
        email = request.form.get('tl_email')
        password = request.form.get('tl_password')
        server = request.form.get('tl_server')
        
        logger.info(f"Connecting to TradeLocker: {email}, {account_type}, {server}")
        
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
        
        if not (200 <= response.status_code < 300):
            session['error_message'] = f"Authentication failed: {response.status_code} - {response.text}"
            return redirect(url_for('accounts'))
        
        jwt_data = response.json()
        access_token = jwt_data.get('accessToken')
        
        if not access_token:
            session['error_message'] = "Failed to get access token from TradeLocker"
            return redirect(url_for('accounts'))
        
        # Store token and login info in session
        session['tradelocker_token'] = access_token
        session['tradelocker_env'] = account_type
        session['tradelocker_login_info'] = {
            'email': email,
            'server': server,
            'env': account_type
        }
        
        # Get all accounts using the correct API endpoint
        all_accounts_url = f"{base_url}/backend-api/auth/jwt/all-accounts"
        headers = {
            'Authorization': f'Bearer {access_token}',
            'accept': 'application/json'
        }
        
        accounts_response = requests.get(all_accounts_url, headers=headers, timeout=30)
        
        if not (200 <= accounts_response.status_code < 300):
            session['error_message'] = f"Failed to fetch accounts: {accounts_response.status_code} - {accounts_response.text}"
            return redirect(url_for('accounts'))
        
        accounts_data = accounts_response.json()
        logger.info(f"Raw accounts response: {accounts_data}")
        
        # Format accounts for display - handle different response structures
        formatted_accounts = []
        
        # Handle different possible response structures
        if isinstance(accounts_data, dict) and 'accounts' in accounts_data:
            accounts_list = accounts_data['accounts']
        elif isinstance(accounts_data, list):
            accounts_list = accounts_data
        else:
            # Fallback - try to find accounts in the response
            accounts_list = accounts_data.get('data', accounts_data)
            if not isinstance(accounts_list, list):
                accounts_list = [accounts_data] if accounts_data else []
        
        for account in accounts_list:
            # Handle different field names that TradeLocker might use
            account_id = (account.get('id') or 
                         account.get('accNum') or 
                         account.get('accountNumber') or 
                         account.get('account_id'))
            
            account_balance = (account.get('accountBalance') or 
                             account.get('balance') or 
                             account.get('current_balance') or 
                             '0.00')
            
            currency = account.get('currency', 'USD')
            account_name = account.get('name', f'Account {account_id}')
            
            if account_id:
                formatted_accounts.append({
                    'id': str(account_id),
                    'label': f"{account_name} ({currency} {account_balance})",
                    'balance': str(account_balance),
                    'currency': currency,
                    'acc_num': str(account.get('accNum', account_id)),
                    'name': account_name
                })
        
        # Store accounts in session for selection
        session['tradelocker_accounts'] = formatted_accounts
        logger.info(f"Formatted {len(formatted_accounts)} accounts for selection")
        
        if formatted_accounts:
            session['success_message'] = f"Successfully found {len(formatted_accounts)} account(s). Please select accounts to add below."
        else:
            session['error_message'] = "No accounts found for this user"
            
        return redirect(url_for('accounts'))
        
    except Exception as e:
        logger.error(f"TradeLocker connection error: {str(e)}")
        session['error_message'] = f"Error connecting to TradeLocker: {str(e)}"
        return redirect(url_for('accounts'))

def handle_tradelocker_accounts_addition():
    """Handle adding multiple selected TradeLocker accounts"""
    try:
        selected_account_ids = request.form.getlist('selected_accounts')
        tradelocker_accounts = session.get('tradelocker_accounts', [])
        
        if not selected_account_ids or not tradelocker_accounts:
            session['error_message'] = "No accounts selected or session expired"
            return redirect(url_for('accounts'))
        
        # Find selected accounts
        selected_accounts = []
        for account in tradelocker_accounts:
            if account['id'] in selected_account_ids:
                selected_accounts.append(account)
        
        if not selected_accounts:
            session['error_message'] = "Selected accounts not found"
            return redirect(url_for('accounts'))
        
        # Save accounts to database
        conn = get_connection()
        if not conn:
            session['error_message'] = 'Database connection error'
            return redirect(url_for('accounts'))
        
        cursor = conn.cursor()
        login_info = session.get('tradelocker_login_info', {})
        added_count = 0
        
        for account in selected_accounts:
            try:
                # Check if account already exists for this user
                cursor.execute("""
                    SELECT id FROM trading_accounts 
                    WHERE user_id = %s AND account_id = %s
                """, (current_user.id, account['id']))
                
                if cursor.fetchone():
                    logger.warning(f"Account {account['id']} already exists for user {current_user.id}")
                    continue
                
                # Insert new account with TradeLocker-specific fields
                cursor.execute("""
                    INSERT INTO trading_accounts 
                    (user_id, account_type, account_id, account_name, starting_balance, current_balance, 
                     tl_email, tl_server, account_number, account_env, is_active, created_at, last_updated) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    current_user.id,
                    'tradelocker',
                    account['id'],
                    account['name'],
                    float(account['balance']) if account['balance'] else 100.0,
                    float(account['balance']) if account['balance'] else 100.0,
                    login_info.get('email', ''),
                    login_info.get('server', ''),
                    account['acc_num'],
                    login_info.get('env', 'demo'),
                    1 if added_count == 0 else 0,  # First account is active
                    datetime.now(),
                    datetime.now()
                ))
                added_count += 1
                
            except Exception as e:
                logger.error(f"Error adding account {account['id']}: {str(e)}")
                continue
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Clear session data after successful addition
        session.pop('tradelocker_accounts', None)
        session.pop('tradelocker_token', None)
        session.pop('tradelocker_env', None)
        session.pop('tradelocker_login_info', None)
        
        if added_count > 0:
            flash(f'Successfully added {added_count} trading account(s)!', 'success')
        else:
            flash('No new accounts were added. They may already exist.', 'warning')
        
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"TradeLocker accounts addition error: {str(e)}")
        session['error_message'] = f"Error adding accounts: {str(e)}"
        return redirect(url_for('accounts'))
# Add a route to clear TradeLocker session if needed
@app.route('/clear_tradelocker_session', methods=['POST']) 
@login_required
def clear_tradelocker_session():
    """Clear TradeLocker session data"""
    session.pop('tradelocker_accounts', None)
    session.pop('tradelocker_token', None)
    session.pop('tradelocker_env', None)
    session.pop('tradelocker_login_info', None)
    
    return redirect(url_for('accounts'))
# Add route to set default account (from Traders Impulse pattern)
@app.route('/set_default_account', methods=['POST'])
@login_required
def set_default_account():
    """Set a specific account as the default/active account"""
    try:
        account_id = request.form.get('account_id')
        
        if not account_id:
            flash('No account ID provided', 'error')
            return redirect(url_for('dashboard'))
        
        conn = get_connection()
        if not conn:
            flash('Database connection error', 'error')
            return redirect(url_for('dashboard'))
        
        cursor = conn.cursor()
        
        # First, deactivate all accounts for this user
        cursor.execute("""
            UPDATE trading_accounts SET is_active = 0 WHERE user_id = %s
        """, (current_user.id,))
        
        # Then activate the selected account
        cursor.execute("""
            UPDATE trading_accounts SET is_active = 1 
            WHERE user_id = %s AND account_id = %s
        """, (current_user.id, account_id))
        
        if cursor.rowcount > 0:
            conn.commit()
            flash(f'Account {account_id} set as default', 'success')
        else:
            flash('Account not found', 'error')
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        logger.error(f"Error setting default account: {e}")
        flash('Error setting default account', 'error')
    
    return redirect(url_for('dashboard'))

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
                (user_id, account_type, account_number, mt5_password, mt5_server, starting_balance, current_balance, is_active) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (current_user.id, account_type, account_number, password, server, 100.0, 100.0, 1))
        
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

# Also add a route to clear any stale flash messages
@app.route('/clear-messages')
def clear_messages():
    """Clear any flash messages and redirect to accounts"""
    # This will clear any existing flash messages
    list(get_flashed_messages())  # Consuming the messages clears them
    return redirect(url_for('accounts'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
