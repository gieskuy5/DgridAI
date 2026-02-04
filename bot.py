import requests
import time
import random
from eth_account import Account
from eth_account.messages import encode_defunct
from urllib.parse import urlparse, parse_qs
from web3 import Web3

# =============================
# CONFIG
# =============================
REFF_FILE = "reff.txt"
DATA_X_FILE = "dataX.txt"
WALLET_FILE = "wallet.txt"

BNB_RPC_LIST = [
    "https://bsc-dataseed1.binance.org/",
    "https://bsc-dataseed2.binance.org/",
    "https://bsc-dataseed3.binance.org/",
    "https://bsc.publicnode.com",
    "https://binance.llamarpc.com",
]
ACTIVATE_CONTRACT = "0x73eeC8dC8BBeB75033E04f67B186B1589082e0D0"
ACTIVATE_METHOD_ID = "0x0f15f4c0"

# =============================
# UTILITIES
# =============================
def load_config():
    """Load configuration from config.json"""
    try:
        import json
        with open("config.json", "r") as f:
            return json.load(f)
    except:
        # Return default config if file doesn't exist
        return {
            "captcha": {
                "api_key": "1AWbkb0rj2Cls2CNajIpLO8Aurop3NtY",
                "sitekey": "0x4AAAAAACWrJYbcjOjaTq3u",
                "pageurl": "https://dgrid.ai/"
            }
        }

def load_proxies():
    """Load proxy list from proxy.txt (1 proxy per wallet)"""
    proxies = []
    try:
        with open("proxy.txt", "r") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith("#"):
                    proxies.append(line)
    except:
        pass
    return proxies

def get_proxy_dict(proxy_url):
    """Convert proxy URL to requests proxy dict"""
    if not proxy_url:
        return None
    return {
        "http": proxy_url,
        "https": proxy_url
    }

def get_web3():
    """Get connected Web3 instance"""
    for rpc in BNB_RPC_LIST:
        try:
            w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={'timeout': 10}))
            if w3.is_connected():
                return w3
        except:
            continue
    return None

def load_private_keys():
    keys = []
    with open(WALLET_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                if not line.startswith("0x"):
                    line = "0x" + line
                keys.append(line)
    return keys

def load_x_cookies():
    """Load all Twitter cookies from dataX.txt"""
    cookies = []
    with open(DATA_X_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line and "|" in line:
                parts = line.split("|")
                if len(parts) >= 2:
                    cookies.append((parts[0], parts[1]))
    return cookies

def create_x_session(auth_token, ct0, proxies=None):
    """Create X session with specific cookies"""
    s = requests.Session()
    if proxies:
        s.proxies.update(proxies)
    s.cookies.set("auth_token", auth_token, domain=".twitter.com")
    s.cookies.set("ct0", ct0, domain=".twitter.com")
    s.cookies.set("auth_token", auth_token, domain=".x.com")
    s.cookies.set("ct0", ct0, domain=".x.com")
    s.headers.update({
        "accept": "*/*",
        "authorization": "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
        "x-csrf-token": ct0,
        "x-twitter-active-user": "yes",
        "x-twitter-auth-type": "OAuth2Session",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    })
    return s

def get_user_id_from_username(session, username):
    """Get Twitter user ID from username using GraphQL endpoint"""
    import json
    
    url = "https://x.com/i/api/graphql/-oaLodhGbbnzJBACb1kk2Q/UserByScreenName"
    
    variables = {
        "screen_name": username,
        "withGrokTranslatedBio": False
    }
    
    features = {
        "hidden_profile_subscriptions_enabled": True,
        "profile_label_improvements_pcf_label_in_post_enabled": True,
        "responsive_web_profile_redirect_enabled": False,
        "rweb_tipjar_consumption_enabled": False,
        "verified_phone_label_enabled": False,
        "subscriptions_verification_info_is_identity_verified_enabled": True,
        "subscriptions_verification_info_verified_since_enabled": True,
        "highlights_tweets_tab_ui_enabled": True,
        "responsive_web_twitter_article_notes_tab_enabled": True,
        "subscriptions_feature_can_gift_premium": True,
        "creator_subscriptions_tweet_preview_api_enabled": True,
        "responsive_web_graphql_skip_user_profile_image_extensions_enabled": False,
        "responsive_web_graphql_timeline_navigation_enabled": True
    }
    
    field_toggles = {
        "withPayments": False,
        "withAuxiliaryUserLabels": True
    }
    
    params = {
        "variables": json.dumps(variables),
        "features": json.dumps(features),
        "fieldToggles": json.dumps(field_toggles)
    }
    
    try:
        r = session.get(url, params=params)
        
        if r.status_code == 200:
            data = r.json()
            user_data = data.get("data", {}).get("user", {}).get("result", {})
            
            if user_data and user_data.get("__typename") == "User":
                user_id = user_data.get("rest_id")
                if user_id:
                    return user_id, None
        
        return None, f"Error {r.status_code}"
    except Exception as e:
        return None, str(e)

def check_following(session, user_id):
    """Check if already following a user"""
    url = "https://x.com/i/api/1.1/friendships/show.json"
    
    params = {"target_id": user_id}
    
    try:
        r = session.get(url, params=params)
        
        if r.status_code == 200:
            data = r.json()
            relationship = data.get("relationship", {})
            source = relationship.get("source", {})
            return source.get("following", False), None
        else:
            return None, f"Error {r.status_code}"
    except Exception as e:
        return None, str(e)

def follow_user(session, user_id):
    """Follow a user by user_id"""
    url = "https://x.com/i/api/1.1/friendships/create.json"
    
    data = {
        "include_profile_interstitial_type": "1",
        "include_blocking": "1",
        "include_blocked_by": "1",
        "include_followed_by": "1",
        "include_want_retweets": "1",
        "include_mute_edge": "1",
        "include_can_dm": "1",
        "include_can_media_tag": "1",
        "include_ext_is_blue_verified": "1",
        "include_ext_verified_type": "1",
        "include_ext_profile_image_shape": "1",
        "skip_status": "1",
        "user_id": user_id
    }
    
    try:
        r = session.post(url, data=data)
        
        if r.status_code == 200:
            return True, "OK"
        elif r.status_code == 403:
            return False, "Account suspended or protected"
        else:
            return False, f"Error {r.status_code}"
    except Exception as e:
        return False, str(e)

# =============================
# DGRID API FUNCTIONS
# =============================
def solve_turnstile_captcha(config, proxies=None):
    """Solve Cloudflare Turnstile captcha using sctg.xyz API"""
    captcha_config = config.get("captcha", {})
    api_key = captcha_config.get("api_key", "1AWbkb0rj2Cls2CNajIpLO8Aurop3NtY")
    sitekey = captcha_config.get("sitekey", "0x4AAAAAACWrJYbcjOjaTq3u")
    pageurl = captcha_config.get("pageurl", "https://dgrid.ai/")
    
    try:
        # Submit captcha task
        params = {
            "key": api_key,
            "method": "turnstile",
            "pageurl": pageurl,
            "sitekey": sitekey
        }
        
        r = requests.get("https://sctg.xyz/in.php", params=params, proxies=proxies, timeout=30)
        result = r.text.strip()
        
        if "|" not in result:
            return None, f"Captcha submission failed: {result}"
        
        status, task_id = result.split("|", 1)
        
        # Poll for result
        max_wait = 120  # 2 minutes
        poll_interval = 5
        start_time = time.time()
        
        while (time.time() - start_time) < max_wait:
            time.sleep(poll_interval)
            
            poll_params = {
                "key": api_key,
                "id": task_id,
                "action": "get"
            }
            
            poll_response = requests.get("https://sctg.xyz/res.php", params=poll_params, proxies=proxies, timeout=30)
            poll_result = poll_response.text.strip()
            
            if "NOT_READY" not in poll_result and "PROCESSING" not in poll_result:
                if poll_result.startswith("OK|"):
                    # Extract the actual token after OK|
                    token = poll_result.split("|", 1)[1]
                    return token, None
                else:
                    return None, f"Captcha failed: {poll_result}"
        
        return None, "Captcha timeout"
    except Exception as e:
        return None, str(e)

def dgrid_auth(address, private_key, proxies=None):
    """Authenticate with DGRID"""
    try:
        r = requests.post("https://api2.dgrid.ai/api/v1/client-user/get-code",
            json={"address": address}, headers={"content-type": "application/json"}, proxies=proxies, timeout=30)
        
        if r.status_code != 200 or not r.text:
            raise Exception(f"get-code failed: HTTP {r.status_code}")
        
        data = r.json()
        if "data" not in data or "code" not in data.get("data", {}):
            raise Exception(f"get-code invalid response: {r.text[:100]}")
        
        code = data["data"]["code"]
        
        msg = encode_defunct(text=code)
        sig = Account.sign_message(msg, private_key)
        signature = "0x" + sig.signature.hex()
        
        invite = ""
        try:
            with open(REFF_FILE, "r") as f:
                invite = f.readline().strip()
        except:
            pass
        
        r = requests.post("https://api2.dgrid.ai/api/v1/client-user/challenge",
            json={"address": address, "signature": signature, "inviteCode": invite}, proxies=proxies, timeout=30)
        
        if r.status_code != 200 or not r.text:
            raise Exception(f"challenge failed: HTTP {r.status_code}")
        
        data = r.json()
        if "data" not in data or "token" not in data.get("data", {}):
            raise Exception(f"challenge invalid: {r.text[:100]}")
        
        return data["data"]["token"]
    except requests.exceptions.JSONDecodeError as e:
        raise Exception(f"Auth API returned invalid JSON: {str(e)}")
    except requests.exceptions.RequestException as e:
        raise Exception(f"Auth network error: {str(e)}")

def bind_invite(token, proxies=None):
    try:
        with open(REFF_FILE, "r") as f:
            code = f.readline().strip()
        r = requests.post(f"https://api2.dgrid.ai/api/v1/invite-code/{code}/bind-relation",
            headers={"authorization": f"Bearer {token}"}, proxies=proxies)
        return "success" in r.text.lower() or "already" in r.text.lower()
    except:
        return False

def bind_x(token, auth_token, ct0, proxies=None):
    """Auto bind X/Twitter with specific account"""
    try:
        x_session = create_x_session(auth_token, ct0)
        
        r = requests.get("https://api2.dgrid.ai/api/v1/me/x-bind",
            headers={"authorization": f"Bearer {token}"},
            params={"redirect": "https://dgrid.ai/arena/activate"}, proxies=proxies)
        
        result = r.json()
        if result.get("code") != "200":
            return "already" in result.get("message", "").lower() or "bound" in result.get("message", "").lower()
        
        auth_url = result["data"]["authUrl"]
        parsed = urlparse(auth_url)
        params = parse_qs(parsed.query)
        
        oauth_params = {
            "client_id": params.get("client_id", [""])[0],
            "code_challenge": params.get("code_challenge", [""])[0],
            "code_challenge_method": params.get("code_challenge_method", [""])[0],
            "redirect_uri": params.get("redirect_uri", [""])[0],
            "response_type": params.get("response_type", [""])[0],
            "scope": params.get("scope", [""])[0],
            "state": params.get("state", [""])[0],
        }
        
        r2 = x_session.get("https://x.com/i/api/2/oauth2/authorize", params=oauth_params)
        if r2.status_code != 200:
            return False
        
        auth_code = r2.json().get("auth_code", "")
        if not auth_code:
            return False
        
        r3 = x_session.post("https://x.com/i/api/2/oauth2/authorize",
            data=f"approval=true&code={auth_code}",
            headers={"content-type": "application/x-www-form-urlencoded"})
        
        if r3.status_code == 200:
            redirect_url = r3.json().get("redirect_uri", "")
            if redirect_url:
                requests.get(redirect_url, allow_redirects=True)
            return True
        return False
    except:
        return False

def claim_follow_mission(token, proxies=None):
    """Claim follow mission reward via sub-verification API"""
    try:
        r = requests.get("https://api2.dgrid.ai/api/v1/me/sub-verification",
            headers={
                "authorization": f"Bearer {token}",
                "accept": "application/json, text/plain, */*"
            }, proxies=proxies, timeout=30)
        if r.status_code == 200:
            data = r.json()
            return True, data
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)

def verify_subscription(token, proxies=None, verbose=False):
    """Verify subscription status from arena/ticket"""
    for attempt in range(5):
        try:
            r = requests.get("https://api2.dgrid.ai/api/v1/arena/ticket",
                headers={
                    "authorization": f"Bearer {token}",
                    "accept": "application/json, text/plain, */*"
                }, proxies=proxies, timeout=30)
            
            if r.status_code == 200:
                data = r.json().get("data", {})
                if data.get("hasSubscribed", False):
                    return True, None
                # Not subscribed yet
                if verbose and attempt == 4:
                    return False, "hasSubscribed=false"
            else:
                if verbose and attempt == 4:
                    return False, f"HTTP {r.status_code}"
        except Exception as e:
            if verbose and attempt == 4:
                return False, str(e)
        time.sleep(3)
    return False, "Max retries exceeded"

def check_ticket(token, proxies=None):
    r = requests.get("https://api2.dgrid.ai/api/v1/arena/ticket",
        headers={"authorization": f"Bearer {token}"}, proxies=proxies)
    if r.status_code == 200:
        return r.json().get("data", {})
    return {}

def get_account_info(token, proxies=None):
    """Get account info including bound Twitter details"""
    try:
        r = requests.get("https://api2.dgrid.ai/api/v1/me",
            headers={
                "authorization": f"Bearer {token}",
                "accept": "application/json, text/plain, */*"
            }, proxies=proxies, timeout=30)
        if r.status_code == 200:
            return r.json().get("data", {})
    except:
        pass
    return {}

def complete_missions(token, config, proxies=None):
    """Complete all daily missions with Turnstile captcha verification"""
    # Solve Turnstile captcha first
    captcha_token, captcha_err = solve_turnstile_captcha(config, proxies)
    if captcha_err:
        print(f"   ⚠ Captcha error: {captcha_err}")
        return 0, 0
    
    # Include captcha token in headers
    headers = {
        "authorization": f"Bearer {token}",
        "accept": "application/json, text/plain, */*",
        "cf-turnstile-response": captcha_token
    }
    
    r = requests.get("https://api2.dgrid.ai/api/v1/arena/missions?locale=en", headers=headers, proxies=proxies)
    
    if r.status_code != 200:
        return 0, 0
    
    data = r.json().get("data", {})
    group_id = data.get("group_id", "")
    missions = data.get("missions", [])
    
    total_pts = 0
    completed = 0
    
    for m in missions:
        if m.get("dealt"):
            total_pts += m.get("get_points", 0)
            continue
        
        answers = m.get("answers_ids", [])
        if len(answers) >= 2:
            answer = answers[random.randint(0, 1)]
            url = f"https://api2.dgrid.ai/api/v1/arena/missions/{group_id}/questions/{m['question_id']}/options/{answer}"
            r = requests.post(url, headers={"authorization": f"Bearer {token}", "content-type": "application/json"}, json={}, proxies=proxies)
            if r.status_code == 200:
                pts = r.json().get("data", {}).get("reward", 0)
                total_pts += pts
                completed += 1
            time.sleep(1)
    
    return completed, total_pts

def get_leaderboard(token, proxies=None):
    r = requests.get("https://api2.dgrid.ai/api/v1/arena/leaderboard/me",
        headers={"authorization": f"Bearer {token}"}, proxies=proxies)
    if r.status_code == 200:
        return r.json().get("data", {})
    return {}

# =============================
# CHAIN FUNCTIONS
# =============================
def sign_chain(w3, private_key, address):
    """Execute activate() on BNB"""
    try:
        balance = w3.eth.get_balance(address)
        gas_price = w3.eth.gas_price
        gas_limit = 100000
        estimated_cost = gas_price * gas_limit
        
        # Check if balance is enough for gas
        if balance < estimated_cost:
            balance_bnb = w3.from_wei(balance, 'ether')
            cost_bnb = w3.from_wei(estimated_cost, 'ether')
            return False, f"Insufficient BNB (have: {balance_bnb:.6f}, need: {cost_bnb:.6f})"
        
        tx = {
            'nonce': w3.eth.get_transaction_count(address),
            'to': Web3.to_checksum_address(ACTIVATE_CONTRACT),
            'value': 0,
            'gas': gas_limit,
            'gasPrice': gas_price,
            'data': ACTIVATE_METHOD_ID,
            'chainId': 56
        }
        
        signed = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        
        return receipt['status'] == 1, tx_hash.hex()
    except Exception as e:
        return False, str(e)

def transfer_all_balance(w3, from_pk, to_address):
    """Transfer remaining BNB to next wallet, keeping 0.0001 BNB reserve"""
    try:
        from_account = Account.from_key(from_pk)
        from_address = from_account.address
        
        balance = w3.eth.get_balance(from_address)
        gas_price = w3.eth.gas_price
        gas_limit = 21000
        gas_cost = gas_price * gas_limit
        
        # Keep 0.0001 BNB reserve for future transactions
        reserve = w3.to_wei(0.0001, 'ether')
        
        if balance <= gas_cost + reserve:
            return False, "No balance to transfer"
        
        amount = balance - gas_cost - reserve
        
        tx = {
            'nonce': w3.eth.get_transaction_count(from_address),
            'to': Web3.to_checksum_address(to_address),
            'value': amount,
            'gas': gas_limit,
            'gasPrice': gas_price,
            'chainId': 56
        }
        
        signed = w3.eth.account.sign_transaction(tx, from_pk)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        
        return True, w3.from_wei(amount, 'ether')
    except Exception as e:
        return False, str(e)

# =============================
# MAIN PROCESS
# =============================
def try_x_bind_and_claim(token, auth_token, ct0, x_index, dgrid_user_id, proxies=None):
    """Try to bind X, follow @dgrid_ai, and claim follow mission. Returns (success, error_type, message)"""
    # X Bind
    x_ok = bind_x(token, auth_token, ct0, proxies)
    if not x_ok:
        return False, "x_bind", f"X Bind failed (Twitter #{x_index})"
    
    # Follow @dgrid_ai
    x_session = create_x_session(auth_token, ct0, proxies)
    
    # Check if already following
    is_following, check_err = check_following(x_session, dgrid_user_id)
    
    if check_err:
        # Error checking, but continue anyway
        pass
    elif is_following:
        # Already following, skip
        pass
    else:
        # Not following yet, do follow
        follow_ok, follow_msg = follow_user(x_session, dgrid_user_id)
        if not follow_ok:
            # Follow failed, but continue with claim attempt
            pass
    
    # Claim follow mission reward
    claim_ok, claim_result = claim_follow_mission(token, proxies)
    if claim_ok:
        return True, None, f"OK (Twitter #{x_index})"
    
    # Even if claim fails, X Bind was successful - continue
    return True, None, f"OK (Twitter #{x_index}) - claim pending"

def process_wallet(w3, private_key, available_x_cookies, used_x_indices, index, total, config, proxies, next_address=None, dgrid_user_id=None):
    """Process wallet with Twitter fallback support"""
    account = Account.from_key(private_key)
    address = account.address
    
    print(f"\n[{index}/{total}] {address}")
    
    try:
        # Auth
        token = dgrid_auth(address, private_key, proxies)
        print("   ✓ Auth OK")
        
        # Check current status first
        ticket = check_ticket(token, proxies)
        has_x = ticket.get("hasBoundX", False)
        has_sub = ticket.get("hasSubscribed", False)
        has_chain = ticket.get("hasSignedChain", False)
        is_done = ticket.get("done", False)
        
        # If already complete, skip bind/subscribe/chain process
        if is_done and has_x and has_sub and has_chain:
            print("   ✓ X Bind: Already done")
            print("   ✓ Follow Claim: Already done")
            print("   ✓ Chain: Already signed")
            
            # Just do missions and show leaderboard
            completed, pts = complete_missions(token, config, proxies)
            print(f"   ✓ Missions: +{pts} pts ({completed} new)")
            
            # Claim follow mission reward
            follow_claimed, _ = claim_follow_mission(token, proxies)
            if follow_claimed:
                print("   ✓ Follow Mission: Claimed")
            
            lb = get_leaderboard(token, proxies)
            print(f"   ✓ Rank: #{lb.get('rank', 0)} | Weekly: {lb.get('weeklyPoints', 0)} pts")
            
            # Transfer to next wallet if success
            if next_address:
                success, result = transfer_all_balance(w3, private_key, next_address)
                if success:
                    print(f"   ✓ Transfer: {result:.6f} BNB → next wallet")
                else:
                    print(f"   - Transfer: {result}")
            
            print("   ✅ COMPLETE! (already done)")
            return True, "Already complete", None
        
        # Bind invite
        bind_invite(token, proxies)
        
        # Check if X bind and subscribe needed
        if has_x and has_sub:
            print("   ✓ X Bind: Already done")
            print("   ✓ Follow Claim: Already done")
            used_x_index = None
        else:
            # Pool-based: use next available Twitter account from pool
            x_success = False
            used_x_index = None
            
            # Find next unused Twitter account
            for x_idx, x_cookie in enumerate(available_x_cookies):
                if x_idx in used_x_indices:
                    continue  # Skip already used Twitter accounts
                
                auth_token, ct0 = x_cookie
                print(f"   🐦 Using Twitter #{x_idx + 1} from pool...")
                
                success, error_type, message = try_x_bind_and_claim(token, auth_token, ct0, x_idx + 1, dgrid_user_id, proxies)
                
                if success:
                    print(f"   ✓ X Bind: OK")
                    print(f"   ✓ Follow: @dgrid_ai")
                    print(f"   ✓ Follow Claim: OK")
                    x_success = True
                    used_x_index = x_idx
                    break
                else:
                    print(f"   ✗ {message}")
                    if error_type == "x_bind":
                        print(f"   ↻ Trying next Twitter from pool...")
            
            if not x_success:
                if not available_x_cookies:
                    print("   ✗ No Twitter accounts in pool")
                    return False, "No Twitter data", None
                print("   ✗ All Twitter accounts in pool failed or used")
                return False, "Twitter pool exhausted", None
            
            # Mark this Twitter account as used
            if used_x_index is not None:
                used_x_indices.add(used_x_index)
        
        # Refresh status
        ticket = check_ticket(token, proxies)
        chain_signed = ticket.get("hasSignedChain", False)
        
        # Sign chain if needed (critical step with retry)
        if not chain_signed:
            time.sleep(5)  # Wait for API sync
            
            max_chain_retries = 3
            for chain_attempt in range(max_chain_retries):
                success, result = sign_chain(w3, private_key, address)
                if success:
                    print(f"   ✓ Chain: TX {result[:16]}...")
                    chain_signed = True  # TX sent successfully, consider it done
                    break
                else:
                    # Check if actually signed
                    ticket = check_ticket(token, proxies)
                    if ticket.get("hasSignedChain"):
                        chain_signed = True
                        print("   ✓ Chain: Already signed (confirmed)")
                        break
                    
                    if "Insufficient" in result:
                        print(f"   ✗ Chain: {result}")
                        return False, result, used_x_index
                    
                    if chain_attempt < max_chain_retries - 1:
                        print(f"   ⚠ Chain attempt {chain_attempt + 1} failed, retrying in 15s...")
                        time.sleep(15)
                    else:
                        print(f"   ✗ Chain: {result}")
                        return False, "Chain signing failed", used_x_index
        else:
            print("   ✓ Chain: Already signed")
        
        # Missions
        completed, pts = complete_missions(token, config, proxies)
        print(f"   ✓ Missions: +{pts} pts ({completed} new)")
        
        # Claim follow mission reward
        follow_claimed, follow_result = claim_follow_mission(token, proxies)
        if follow_claimed:
            print("   ✓ Follow Mission: Claimed")
        
        # Leaderboard
        lb = get_leaderboard(token, proxies)
        print(f"   ✓ Rank: #{lb.get('rank', 0)} | Weekly: {lb.get('weeklyPoints', 0)} pts")
        
        # Transfer to next wallet if success
        if next_address:
            success, result = transfer_all_balance(w3, private_key, next_address)
            if success:
                print(f"   ✓ Transfer: {result:.6f} BNB → next wallet")
            else:
                print(f"   - Transfer: {result}")
        
        print("   ✅ COMPLETE!")
        return True, "Success", used_x_index
        
    except Exception as e:
        print(f"   ✗ Error: {str(e)}")
        return False, str(e), None

def main():
    print("""
╔═════════════════════════════════════════╗
║  DGRID AI AUTO BOT                      ║
║  https://t.me/MDFKOfficial              ║
╚═════════════════════════════════════════╝""")
    
    # Load configuration
    config = load_config()
    proxy_list = load_proxies()
    
    # Connect to BNB
    w3 = get_web3()
    if not w3:
        print("✗ Failed to connect to BNB RPC")
        return
    print("✓ Connected to BNB")
    
    # Load wallets and Twitter cookies
    private_keys = load_private_keys()
    x_cookies = load_x_cookies()
    
    if not private_keys:
        print("✗ No wallets in wallet.txt")
        return
    
    # Get all addresses for transfer
    addresses = [Account.from_key(pk).address for pk in private_keys]
    
    if not x_cookies:
        print("⚠ No Twitter accounts in dataX.txt (only already-bound wallets will be processed)")
    
    print(f"✓ Loaded {len(private_keys)} wallet(s), {len(x_cookies)} Twitter account(s)")
    
    if proxy_list:
        print(f"✓ Loaded {len(proxy_list)} proxy(ies)")
    else:
        print("⚠ No proxies loaded (will use direct connection)")
    
    # Get @dgrid_ai user ID once (for follow functionality)
    dgrid_user_id = None
    if x_cookies:
        try:
            temp_auth, temp_ct0 = x_cookies[0]
            # Use first proxy if available for initial request
            temp_proxy = get_proxy_dict(proxy_list[0]) if proxy_list else None
            temp_session = create_x_session(temp_auth, temp_ct0, temp_proxy)
            dgrid_user_id, err = get_user_id_from_username(temp_session, "dgrid_ai")
            if dgrid_user_id:
                print(f"✓ Target follow: @dgrid_ai (ID: {dgrid_user_id})")
        except:
            pass
    
    success = 0
    failed = 0
    used_x_indices = set()  # Track which Twitter accounts have been used successfully
    
    for i, pk in enumerate(private_keys):
        # Next address for balance transfer (if not last wallet)
        next_addr = addresses[i + 1] if i + 1 < len(addresses) else None
        
        # 1:1 proxy mapping: use proxy at same index as wallet
        proxy_url = proxy_list[i] if i < len(proxy_list) else None
        proxies = get_proxy_dict(proxy_url)
        
        if proxy_url:
            print(f"\n[{i + 1}/{len(private_keys)}] Using proxy: {proxy_url}")
        
        result, msg, used_idx = process_wallet(w3, pk, x_cookies, used_x_indices, i + 1, len(private_keys), config, proxies, next_addr, dgrid_user_id)
        
        if result:
            success += 1
        else:
            failed += 1
            print(f"\n⚠️ Wallet {i + 1} failed: {msg}")
            # Continue to next wallet instead of stopping
            print("   ↻ Continuing to next wallet...")
        
        if i + 1 < len(private_keys):
            time.sleep(3)
    
    print(f"\n{'='*45}")
    print(f"📊 SUMMARY:")
    print(f"   ✓ Success: {success}")
    print(f"   ✗ Failed:  {failed}")
    print(f"   🐦 Twitter used: {len(used_x_indices)}/{len(x_cookies)}")
    print('='*45)

if __name__ == "__main__":
    main()

