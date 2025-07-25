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
