---
name: grant-login
description: Authenticate to CyberArk SCA via grant login using credentials from .env
---

# grant-login

Authenticate to CyberArk SCA by driving the interactive `grant login` flow via tmux.

## Prerequisites

- `grant` binary built and on PATH (or use `./grant`)
- `.env` file at project root with:
  ```
  SCA_PASSWORD=<password>
  SCA_TOTP_SECRET=<base32-encoded TOTP secret>
  ```
- `tmux` installed
- `python3` available (for TOTP generation — uses only stdlib modules)

## Steps

1. **Read credentials** from `.env` at the project root:
   ```bash
   source .env
   ```

2. **Start a tmux session** for the interactive login:
   ```bash
   tmux new-session -d -s grant-login -x 200 -y 50 'grant login'
   ```

3. **Wait for the password prompt**, then send the password:
   ```bash
   sleep 2
   # Check for password prompt
   tmux capture-pane -t grant-login -p | tail -5
   tmux send-keys -t grant-login "$SCA_PASSWORD" Enter
   ```

4. **Wait for the MFA method selection**, then select "OATH Code":
   ```bash
   sleep 3
   tmux capture-pane -t grant-login -p | tail -10
   # The menu defaults to Email (second item). OATH Code is the first item.
   # Navigate up to select it, then press Enter.
   tmux send-keys -t grant-login Up Enter
   ```

5. **Generate a fresh TOTP code** using python3 (no extra deps):
   ```bash
   TOTP_CODE=$(python3 -c "
   import hmac, hashlib, struct, time, base64
   secret = base64.b32decode('$SCA_TOTP_SECRET', casefold=True)
   counter = struct.pack('>Q', int(time.time()) // 30)
   h = hmac.new(secret, counter, hashlib.sha1).digest()
   offset = h[-1] & 0x0F
   code = (struct.unpack('>I', h[offset:offset+4])[0] & 0x7FFFFFFF) % 1000000
   print(f'{code:06d}')
   ")
   ```

6. **Send the TOTP code**:
   ```bash
   sleep 2
   tmux send-keys -t grant-login "$TOTP_CODE" Enter
   ```

7. **Capture and verify the result**:
   ```bash
   sleep 5
   tmux capture-pane -t grant-login -p
   ```
   Expected success output contains: `Successfully authenticated as`

8. **Clean up the tmux session**:
   ```bash
   tmux kill-session -t grant-login 2>/dev/null
   ```

## Troubleshooting

- If the MFA menu doesn't show "OATH Code", capture the pane to see available options
- If TOTP code is rejected, check that system clock is synced (TOTP is time-sensitive)
- Increase sleep durations if the Identity platform is slow to respond
- Use `tmux capture-pane -t grant-login -p` at any point to inspect current state
