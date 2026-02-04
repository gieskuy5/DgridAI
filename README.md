# DGRID AI Auto Bot

An automated bot for DGRID.ai platform with Cloudflare Turnstile captcha solving and proxy support.

## Features

- **Multi-Wallet Support** - Process multiple wallets sequentially
- **Cloudflare Turnstile Captcha Solver** - Auto-solve captcha for missions
- **Proxy Support** - 1:1 proxy mapping per wallet (HTTP/HTTPS/SOCKS5)
- **Auto X/Twitter Binding** - Automatically bind Twitter accounts with pool-based fallback
- **Auto Follow** - Automatically follow @dgrid_ai before claiming mission
- **Chain Signing** - Execute activate() transaction on BNB Chain
- **Daily Missions** - Auto-complete daily quiz missions with captcha bypass
- **Balance Transfer** - Automatically transfer remaining BNB to next wallet
- **Leaderboard Tracking** - Display rank and weekly points

## Requirements

```bash
pip install requests web3 eth-account
```

## Configuration Files

### `config.json`
Captcha API configuration:
```json
{
  "captcha": {
    "api_key": "YOUR_CAPTCHA_API_KEY",
    "sitekey": "0x4AAAAAACWrJYbcjOjaTq3u",
    "pageurl": "https://dgrid.ai/"
  }
}
```

### `proxy.txt`
Proxy list (one proxy per line, 1:1 mapping with wallets):
```
http://proxy1.example.com:8080
http://user:pass@proxy2.example.com:3128
socks5://proxy3.example.com:1080
```
- **1:1 Mapping**: Wallet 1 uses proxy line 1, Wallet 2 uses proxy line 2, etc.
- **Optional**: Leave empty or delete file to use direct connection
- **Formats**: HTTP, HTTPS, SOCKS5 with optional authentication

### `wallet.txt`
Private keys (one per line):
```
0x1234...abcd
5678...efgh
```

### `dataX.txt`
Twitter credentials (format: `auth_token|ct0`):
```
abc123token|xyz789ct0
def456token|uvw321ct0
```

### `reff.txt`
Referral/invite code (single line):
```
YOUR_INVITE_CODE
```

## Usage

```bash
python bot.py
```

## How It Works

1. **Load Configuration** - Reads config.json and proxy.txt
2. **Proxy Assignment** - Maps each wallet to its corresponding proxy (1:1)
3. **Authentication** - Signs message to authenticate with DGRID API (via proxy)
4. **Invite Binding** - Binds referral code from `reff.txt`
5. **X/Twitter Bind** - OAuth2 authentication to bind Twitter account
6. **Follow @dgrid_ai** - Automatically follows before claiming mission
7. **Follow Mission Claim** - Claims subscription reward
8. **Chain Signing** - Executes activate() on BNB contract `0x73eeC8dC8BBeB75033E04f67B186B1589082e0D0`
9. **Captcha Solving** - Solves Cloudflare Turnstile before accessing missions
10. **Missions** - Completes daily quiz missions for points
11. **Leaderboard** - Shows rank and weekly points
12. **Transfer** - Sends remaining BNB to next wallet in queue

## Captcha System

The bot uses [sctg.xyz](https://sctg.xyz) API to solve Cloudflare Turnstile captcha:
- **Auto-solve**: Captcha is solved automatically before missions
- **Success rate**: ~95% with proper API key
- **Timeout**: 2 minutes maximum per solve
- **Fallback**: Returns 0 points if captcha fails

## Proxy System

**1:1 Account-Proxy Mapping:**
- Each wallet uses the proxy at the same line number in `proxy.txt`
- Supports HTTP, HTTPS, and SOCKS5 protocols
- Optional authentication with `user:pass@host:port`
- If more wallets than proxies: extra wallets use direct connection

**Example:**
```
Wallet 1 → Proxy line 1
Wallet 2 → Proxy line 2
Wallet 3 → Proxy line 3
```

**All requests use proxy:**
- DGRID API authentication
- Twitter/X OAuth
- Captcha solving API
- Mission completion
- Leaderboard queries

## Status Indicators

| Icon | Meaning |
|------|---------|
| ✓ | Success |
| ✗ | Failed |
| ⚠ | Warning |
| ↻ | Retrying |
| 🐦 | Twitter action |
| ✅ | Complete |

## Important Notes

- Each Twitter account can only be bound to one wallet
- Minimum BNB required for chain signing (~0.0001 BNB for gas)
- Failed wallets are skipped, processing continues to next
- **Captcha API**: Requires valid API key in `config.json`
- **Proxy format**: Must be valid URL (http://, https://, or socks5://)
- **1:1 Mapping**: Ensure proxy count matches wallet count for full coverage

## Troubleshooting

**Captcha errors:**
- Check API key in `config.json`
- Verify sctg.xyz service is online
- Check proxy connection if using proxies

**Proxy errors:**
- Verify proxy format is correct
- Test proxy connection manually
- Check authentication credentials

**Twitter binding fails:**
- Verify auth_token and ct0 are valid
- Check if Twitter account is not suspended
- Try different Twitter account from pool

## Telegram

Join: https://t.me/MDFKOfficial
