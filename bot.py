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

def create_x_session(auth_token, ct0):
    """Create X session with specific cookies"""
    s = requests.Session()
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

# =============================
# DGRID API FUNCTIONS
# =============================
def dgrid_auth(address, private_key):
    """Authenticate with DGRID"""
    try:
        r = requests.post("https://api2.dgrid.ai/api/v1/client-user/get-code",
            json={"address": address}, headers={"content-type": "application/json"}, timeout=30)
        
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
            json={"address": address, "signature": signature, "inviteCode": invite}, timeout=30)
        
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

def bind_invite(token):
    try:
        with open(REFF_FILE, "r") as f:
            code = f.readline().strip()
        r = requests.post(f"https://api2.dgrid.ai/api/v1/invite-code/{code}/bind-relation",
            headers={"authorization": f"Bearer {token}"})
        return "success" in r.text.lower() or "already" in r.text.lower()
    except:
        return False

def bind_x(token, auth_token, ct0):
    """Auto bind X/Twitter with specific account"""
    try:
        x_session = create_x_session(auth_token, ct0)
        
        r = requests.get("https://api2.dgrid.ai/api/v1/me/x-bind",
            headers={"authorization": f"Bearer {token}"},
            params={"redirect": "https://dgrid.ai/arena/activate"})
        
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

def claim_follow_mission(token):
    """Claim follow mission reward via sub-verification API"""
    try:
        r = requests.get("https://api2.dgrid.ai/api/v1/me/sub-verification",
            headers={
                "authorization": f"Bearer {token}",
                "accept": "application/json, text/plain, */*"
            }, timeout=30)
        if r.status_code == 200:
            data = r.json()
            return True, data
        return False, f"HTTP {r.status_code}"
    except Exception as e:
        return False, str(e)

def verify_subscription(token, verbose=False):
    """Verify subscription status from arena/ticket"""
    for attempt in range(5):
        try:
            r = requests.get("https://api2.dgrid.ai/api/v1/arena/ticket",
                headers={
                    "authorization": f"Bearer {token}",
                    "accept": "application/json, text/plain, */*"
                }, timeout=30)
            
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

def check_ticket(token):
    r = requests.get("https://api2.dgrid.ai/api/v1/arena/ticket",
        headers={"authorization": f"Bearer {token}"})
    if r.status_code == 200:
        return r.json().get("data", {})
    return {}

def get_account_info(token):
    """Get account info including bound Twitter details"""
    try:
        r = requests.get("https://api2.dgrid.ai/api/v1/me",
            headers={
                "authorization": f"Bearer {token}",
                "accept": "application/json, text/plain, */*"
            }, timeout=30)
        if r.status_code == 200:
            return r.json().get("data", {})
    except:
        pass
    return {}

def complete_missions(token):
    """Complete all daily missions"""
    r = requests.get("https://api2.dgrid.ai/api/v1/arena/missions?locale=en",
        headers={"authorization": f"Bearer {token}"})
    
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
            r = requests.post(url, headers={"authorization": f"Bearer {token}", "content-type": "application/json"}, json={})
            if r.status_code == 200:
                pts = r.json().get("data", {}).get("reward", 0)
                total_pts += pts
                completed += 1
            time.sleep(1)
    
    return completed, total_pts

def get_leaderboard(token):
    r = requests.get("https://api2.dgrid.ai/api/v1/arena/leaderboard/me",
        headers={"authorization": f"Bearer {token}"})
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
    """Transfer all remaining BNB to next wallet"""
    try:
        from_account = Account.from_key(from_pk)
        from_address = from_account.address
        
        balance = w3.eth.get_balance(from_address)
        gas_price = w3.eth.gas_price
        gas_limit = 21000
        gas_cost = gas_price * gas_limit
        
        if balance <= gas_cost:
            return False, "No balance to transfer"
        
        amount = balance - gas_cost
        
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
def try_x_bind_and_claim(token, auth_token, ct0, x_index):
    """Try to bind X and claim follow mission. Returns (success, error_type, message)"""
    # X Bind
    x_ok = bind_x(token, auth_token, ct0)
    if not x_ok:
        return False, "x_bind", f"X Bind failed (Twitter #{x_index})"
    
    # Claim follow mission reward (assumes follow already done via follow.py)
    claim_ok, claim_result = claim_follow_mission(token)
    if claim_ok:
        return True, None, f"OK (Twitter #{x_index})"
    
    # Even if claim fails, X Bind was successful - continue
    return True, None, f"OK (Twitter #{x_index}) - claim pending"

def process_wallet(w3, private_key, available_x_cookies, used_x_indices, index, total, next_address=None):
    """Process wallet with Twitter fallback support"""
    account = Account.from_key(private_key)
    address = account.address
    
    print(f"\n[{index}/{total}] {address}")
    
    try:
        # Auth
        token = dgrid_auth(address, private_key)
        print("   ✓ Auth OK")
        
        # Check current status first
        ticket = check_ticket(token)
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
            completed, pts = complete_missions(token)
            print(f"   ✓ Missions: +{pts} pts ({completed} new)")
            
            # Claim follow mission reward
            follow_claimed, _ = claim_follow_mission(token)
            if follow_claimed:
                print("   ✓ Follow Mission: Claimed")
            
            lb = get_leaderboard(token)
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
        bind_invite(token)
        
        # Check if X bind and subscribe needed
        if has_x and has_sub:
            print("   ✓ X Bind: Already done")
            print("   ✓ Follow Claim: Already done")
            used_x_index = None
        else:
            # Try X Bind and Subscribe with fallback
            x_success = False
            used_x_index = None
            
            for x_idx, x_cookie in enumerate(available_x_cookies):
                if x_idx in used_x_indices:
                    continue  # Skip already used Twitter accounts
                
                auth_token, ct0 = x_cookie
                print(f"   🐦 Trying Twitter #{x_idx + 1}...")
                
                success, error_type, message = try_x_bind_and_claim(token, auth_token, ct0, x_idx + 1)
                
                if success:
                    print(f"   ✓ X Bind: OK")
                    print(f"   ✓ Follow Claim: OK")
                    x_success = True
                    used_x_index = x_idx
                    break
                else:
                    print(f"   ✗ {message}")
                    if error_type == "x_bind":
                        print(f"   ↻ Trying next Twitter account...")
            
            if not x_success:
                if not available_x_cookies:
                    print("   ✗ No Twitter accounts available")
                    return False, "No Twitter data", None
                print("   ✗ All Twitter accounts failed for this wallet")
                return False, "All Twitter accounts exhausted", None
            
            # Mark this Twitter account as used
            if used_x_index is not None:
                used_x_indices.add(used_x_index)
        
        # Refresh status
        ticket = check_ticket(token)
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
                    ticket = check_ticket(token)
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
        completed, pts = complete_missions(token)
        print(f"   ✓ Missions: +{pts} pts ({completed} new)")
        
        # Claim follow mission reward
        follow_claimed, follow_result = claim_follow_mission(token)
        if follow_claimed:
            print("   ✓ Follow Mission: Claimed")
        
        # Leaderboard
        lb = get_leaderboard(token)
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
    
    if not x_cookies:
        print("✗ No Twitter accounts in dataX.txt")
        return
    
    # Get all addresses for transfer
    addresses = [Account.from_key(pk).address for pk in private_keys]
    
    print(f"✓ Loaded {len(private_keys)} wallet(s), {len(x_cookies)} Twitter account(s)")
    
    success = 0
    failed = 0
    used_x_indices = set()  # Track which Twitter accounts have been used successfully
    
    for i, pk in enumerate(private_keys):
        # Next address for balance transfer (if not last wallet)
        next_addr = addresses[i + 1] if i + 1 < len(addresses) else None
        
        # Check if we have any Twitter accounts left
        available_count = len(x_cookies) - len(used_x_indices)
        if available_count == 0:
            print(f"\n⚠️ No more Twitter accounts available!")
            print(f"   Processed: {i} wallets | Remaining: {len(private_keys) - i} wallets")
            break
        
        result, msg, used_idx = process_wallet(w3, pk, x_cookies, used_x_indices, i + 1, len(private_keys), next_addr)
        
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


