# DGRID AI Auto Bot

An automated bot for DGRID.ai platform that handles wallet registration, Twitter/X binding, chain signing, and daily missions.

## Features

- **Multi-Wallet Support** - Process multiple wallets sequentially
- **Auto X/Twitter Binding** - Automatically bind Twitter accounts with fallback support
- **Chain Signing** - Execute activate() transaction on BNB Chain
- **Daily Missions** - Auto-complete daily quiz missions
- **Balance Transfer** - Automatically transfer remaining BNB to next wallet
- **Leaderboard Tracking** - Display rank and weekly points

## Requirements

```
pip install requests web3 eth-account
```

## Configuration Files

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

1. **Authentication** - Signs message to authenticate with DGRID API
2. **Invite Binding** - Binds referral code from `reff.txt`
3. **X/Twitter Bind** - OAuth2 authentication to bind Twitter
4. **Follow Mission** - Claims follow subscription reward
5. **Chain Signing** - Executes activate() on BNB contract `0x73eeC8dC8BBeB75033E04f67B186B1589082e0D0`
6. **Missions** - Completes daily quiz missions for points
7. **Transfer** - Sends remaining BNB to next wallet in queue

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

## Telegram

Join: https://t.me/MDFKOfficial
