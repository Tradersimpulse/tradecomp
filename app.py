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
from tradelocker import TradeLocker

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

def get_competition_settings():
    """Get all competition settings from database"""
    try:
        conn = get_connection()
        if not conn:
            return None
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM competition_settings WHERE id = 1")
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        
        return result
    except Exception as e:
        logger.error(f"Error getting competition settings: {e}")
        return None


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
        
        # Get competition settings (includes dates, prize, referral link)
        settings = get_competition_settings()
        start_date = settings['start_date'] if settings else None
        end_date = settings['end_date'] if settings else None
        prize_amount = settings['prize_amount'] if settings else None
        
        return render_template('dashboard.html', 
                             account=account_details,
                             has_account=len(user_accounts) > 0,
                             user_accounts=user_accounts,
                             current_account_id=current_account_id,
                             user_position=user_position,
                             top_percentage=top_percentage,
                             start_date=start_date,
                             end_date=end_date,
                             prize_amount=prize_amount,
                             settings=settings)
                             
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('dashboard.html', 
                             has_account=False, 
                             account=None,
                             user_accounts=[],
                             prize_amount=None,
                             settings=None)

@app.route('/accounts', methods=['GET', 'POST'])
@login_required  
def accounts():
    if request.method == 'GET':
        # Clear session data if requested
        if request.args.get('clear') == 'true':
            session.pop('tradelocker_accounts', None)
            session.pop('tradelocker_token', None)
            session.pop('tradelocker_env', None)
            session.pop('tradelocker_login_info', None)
        
        # Get user's full account data for display
        user_accounts = []
        try:
            conn = get_connection()
            if conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("""
                    SELECT 
                        account_id, 
                        account_type, 
                        account_name,
                        sync_status,
                        is_active,
                        created_at
                    FROM trading_accounts 
                    WHERE user_id = %s 
                    ORDER BY created_at DESC
                """, (current_user.id,))
                user_accounts = cursor.fetchall()
                cursor.close()
                conn.close()
        except Exception as e:
            logger.error(f"Error getting user accounts: {e}")
        
        return render_template('accounts.html', user_accounts=user_accounts)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'connect_tradelocker':
            return handle_tradelocker_connection()
        elif action == 'add_tradelocker_accounts':
            return handle_tradelocker_accounts_addition()
        elif action == 'connect_mt5':
            return handle_mt5_connection()
        elif action == 'set_default':
            return handle_set_default_account()
        else:
            flash('Unknown action', 'error')
            return redirect(url_for('accounts'))
            

def handle_tradelocker_connection():
    """Handle TradeLocker API connection - fetch accounts for selection"""
    try:
        account_type = request.form.get('account_type')
        email = request.form.get('email')
        password = request.form.get('password')
        server = request.form.get('server')
        
        if not all([account_type, email, password, server]):
            return jsonify({'success': False, 'error': 'All fields are required'})
        
        logger.info(f"Connecting to TradeLocker: {email}, {account_type}, {server}")
        
        # Initialize TradeLocker API
        tl = TradeLocker(env=account_type)
        
        # Get JWT token
        token_response = tl.get_jwt_token(email, password, server)
        
        if not tl.token:
            return jsonify({'success': False, 'error': 'Failed to authenticate with TradeLocker'})
        
        # Get all accounts
        accounts_response = tl.get_all_accounts()
        
        if not accounts_response:
            return jsonify({'success': False, 'error': 'Failed to fetch accounts'})
        
        # Format accounts for selection
        formatted_accounts = []
        
        # Handle different response structures
        accounts_list = accounts_response
        if isinstance(accounts_response, dict):
            accounts_list = accounts_response.get('accounts', accounts_response.get('data', [accounts_response]))
        
        if not isinstance(accounts_list, list):
            accounts_list = [accounts_list] if accounts_list else []
        
        for account in accounts_list:
            # Handle different field names
            account_id = (account.get('id') or 
                         account.get('accNum') or 
                         account.get('accountNumber') or 
                         account.get('account_id'))
            
            account_balance = (account.get('accountBalance') or 
                             account.get('balance') or 
                             account.get('current_balance') or 
                             0)
            
            currency = account.get('currency', 'USD')
            account_name = account.get('name', f'Account {account_id}')
            
            if account_id:
                formatted_accounts.append({
                    'id': str(account_id),
                    'name': account_name,
                    'label': f"{account_name} ({currency})",
                    'balance': str(account_balance),
                    'currency': currency,
                    'acc_num': str(account.get('accNum', account_id)),
                    'raw_data': account
                })
        
        # Store in session for account selection
        session['tradelocker_accounts'] = formatted_accounts
        session['tradelocker_token'] = tl.token
        session['tradelocker_env'] = account_type
        session['tradelocker_login_info'] = {
            'email': email,
            'password': password,
            'server': server,
            'env': account_type
        }
        
        logger.info(f"Successfully found {len(formatted_accounts)} accounts")
        
        return jsonify({
            'success': True,
            'accounts': formatted_accounts,
            'message': f"Found {len(formatted_accounts)} account(s)"
        })
        
    except Exception as e:
        logger.error(f"TradeLocker connection error: {str(e)}")
        return jsonify({'success': False, 'error': f"Connection failed: {str(e)}"})

def handle_tradelocker_accounts_addition():
    """Handle adding multiple selected TradeLocker accounts to database - Save current_balance, leave starting_balance NULL"""
    try:
        selected_account_ids = request.form.getlist('selected_accounts')
        tradelocker_accounts = session.get('tradelocker_accounts', [])
        login_info = session.get('tradelocker_login_info', {})
        
        if not selected_account_ids or not tradelocker_accounts:
            flash('No accounts selected or session expired', 'error')
            return redirect(url_for('accounts'))
        
        # Find selected accounts
        selected_accounts = []
        for account in tradelocker_accounts:
            if account['id'] in selected_account_ids:
                selected_accounts.append(account)
        
        if not selected_accounts:
            flash('Selected accounts not found', 'error')
            return redirect(url_for('accounts'))
        
        # Save accounts to database
        conn = get_connection()
        if not conn:
            flash('Database connection error', 'error')
            return redirect(url_for('accounts'))
        
        cursor = conn.cursor()
        added_count = 0
        
        for account in selected_accounts:
            try:
                # Check if account already exists for this user
                cursor.execute("""
                    SELECT id FROM trading_accounts 
                    WHERE user_id = %s AND account_id = %s
                """, (current_user.id, account['id']))
                
                if cursor.fetchone():
                    continue
                
                # Insert new TradeLocker account - SAVE current_balance, LEAVE starting_balance NULL
                cursor.execute("""
                    INSERT INTO trading_accounts 
                    (user_id, account_type, account_id, account_name, current_balance,
                     tl_email, tl_password, tl_server, tl_token, account_number, accnum, account_env, 
                     is_active, sync_status, created_at, last_updated) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    current_user.id,
                    'tradelocker',
                    account['id'],
                    account.get('name', 'TradeLocker Account'),
                    float(account.get('balance', 0)) if account.get('balance') else None,  # Save current_balance
                    login_info.get('email', ''),
                    login_info.get('password', ''),
                    login_info.get('server', ''),
                    session.get('tradelocker_token', ''),
                    account['id'],
                    account.get('acc_num', account['id']),
                    login_info.get('env', 'demo'),
                    1,  # is_active - always set new accounts to active
                    'pending',
                    datetime.now(),
                    datetime.now()
                ))
                added_count += 1
                
            except Exception as e:
                logger.error(f"Error adding account {account['id']}: {str(e)}")
                continue
        
        # Commit the changes
        conn.commit()
        cursor.close()
        conn.close()
        
        # Clear session data
        session.pop('tradelocker_accounts', None)
        session.pop('tradelocker_token', None)
        session.pop('tradelocker_env', None)
        session.pop('tradelocker_login_info', None)
        
        if added_count > 0:
            flash(f'Successfully added {added_count} trading account(s)! Waiting for balance sync...', 'success')
        else:
            flash('No new accounts were added. They may already exist.', 'warning')
        
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"TradeLocker accounts addition error: {str(e)}")
        flash(f"Error adding accounts: {str(e)}", 'error')
        return redirect(url_for('accounts'))
        
def handle_mt5_connection():
    """Handle MT5 account addition - No balance data available initially"""
    try:
        account_number = request.form.get('account_number')
        password = request.form.get('password')
        server = request.form.get('server')
        
        if not all([account_number, password, server]):
            flash('Account number, password, and server are required', 'error')
            return redirect(url_for('accounts'))
        
        # Validate server
        allowed_servers = ['PlexyTrade-Server01', 'TradeSmart-Server01']
        if server not in allowed_servers:
            flash('Invalid server selection', 'error')
            return redirect(url_for('accounts'))
        
        conn = get_connection()
        if not conn:
            flash('Database connection error', 'error')
            return redirect(url_for('accounts'))
        
        cursor = conn.cursor()
        
        # Check if account already exists for this user
        cursor.execute("""
            SELECT id FROM trading_accounts 
            WHERE user_id = %s AND account_number = %s AND mt5_server = %s
        """, (current_user.id, account_number, server))
        
        if cursor.fetchone():
            flash('This MT5 account is already connected', 'warning')
            cursor.close()
            conn.close()
            return redirect(url_for('accounts'))
        
        # Set all new accounts as active
        is_active = 1
        
        # Insert new MT5 account - NO BALANCE DATA AVAILABLE INITIALLY
        cursor.execute("""
            INSERT INTO trading_accounts 
            (user_id, account_type, account_number, mt5_password, mt5_server, 
             is_active, sync_status, created_at, last_updated, account_id) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            current_user.id,
            'mt5',
            account_number,
            password,
            server,
            is_active,
            'pending',
            datetime.now(),
            datetime.now(),
            account_number
        ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        flash('MT5 account added successfully! Waiting for balance sync...', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"MT5 connection error: {str(e)}")
        flash(f"Error adding MT5 account: {str(e)}", 'error')
        return redirect(url_for('accounts'))
        
def handle_set_default_account():
    """Set a specific account as the default/active account"""
    try:
        account_id = request.form.get('account_id')
        
        if not account_id:
            flash('No account ID provided', 'error')
            return redirect(url_for('accounts'))
        
        conn = get_connection()
        if not conn:
            flash('Database connection error', 'error')
            return redirect(url_for('accounts'))
        
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
    
    return redirect(url_for('accounts'))

@app.route('/remove_account', methods=['POST'])
@login_required
def remove_account():
    """Remove a trading account"""
    try:
        account_id = request.form.get('account_id')
        
        if not account_id:
            return jsonify({'success': False, 'error': 'No account ID provided'})
        
        conn = get_connection()
        if not conn:
            return jsonify({'success': False, 'error': 'Database connection error'})
        
        cursor = conn.cursor()
        
        # Check if account exists and belongs to user
        cursor.execute("""
            SELECT id FROM trading_accounts 
            WHERE user_id = %s AND account_id = %s
        """, (current_user.id, account_id))
        
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'success': False, 'error': 'Account not found'})
        
        # Remove the account
        cursor.execute("""
            DELETE FROM trading_accounts 
            WHERE user_id = %s AND account_id = %s
        """, (current_user.id, account_id))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            'success': True, 
            'message': f'Account {account_id} removed successfully'
        })
        
    except Exception as e:
        logger.error(f"Error removing account: {e}")
        return jsonify({'success': False, 'error': f'Error removing account: {str(e)}'})


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
    
    # Get competition settings (includes dates and prize)
    settings = get_competition_settings()
    start_date = settings['start_date'] if settings else None
    end_date = settings['end_date'] if settings else None
    prize_amount = settings['prize_amount'] if settings else None
    
    return render_template('leaderboard.html', 
                         leaderboard=leaderboard_data,
                         start_date=start_date,
                         end_date=end_date,
                         prize_amount=prize_amount,
                         settings=settings)

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
        prize_amount = request.form.get('prize_amount')
        
        # Convert prize_amount to float if provided, otherwise set to None
        if prize_amount and prize_amount.strip():
            try:
                prize_amount = float(prize_amount)
            except ValueError:
                flash('Invalid prize amount format', 'error')
                return redirect(url_for('admin'))
        else:
            prize_amount = None
        
        conn = get_connection()
        if not conn:
            flash('Database connection error', 'error')
            return redirect(url_for('admin'))
        
        cursor = conn.cursor()
        
        # Check if settings record exists
        cursor.execute("SELECT id FROM competition_settings WHERE id = 1")
        if cursor.fetchone():
            # Update existing record
            cursor.execute("""
                UPDATE competition_settings 
                SET start_date = %s, end_date = %s, referral_link = %s, prize_amount = %s 
                WHERE id = 1
            """, (start_date, end_date, referral_link, prize_amount))
        else:
            # Insert new record
            cursor.execute("""
                INSERT INTO competition_settings (id, start_date, end_date, referral_link, prize_amount) 
                VALUES (1, %s, %s, %s, %s)
            """, (start_date, end_date, referral_link, prize_amount))
        
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
    
@app.route('/rules')
def rules():
    # Get competition settings for referral link and prize amount
    settings = get_competition_settings()
    prize_amount = settings['prize_amount'] if settings else None
    referral_link = settings['referral_link'] if settings else None
    
    return render_template('rules.html',
                         prize_amount=prize_amount,
                         referral_link=referral_link,
                         settings=settings)
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
