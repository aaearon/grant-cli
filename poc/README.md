# SCA Access API PoC

Mini proof-of-concept to validate the SCA Access API assumptions from the functional design spec (v2.1).

## Goal

Answer the 4 open questions from Section 5.1:

1. What does `/access/elevate` return for Azure?
2. Does `/token/{app_id}` require a pre-registered app?
3. Is the ISP JWT sufficient for SCA Access APIs?
4. What is the exact response schema for `/access/csp/eligibility`?

## Prerequisites

- Go 1.24+
- A `.env` file in the project root (`/home/tim/sca-cli/.env`) with:

```
SCA_USERNAME=<cyberark identity username>
SCA_PASSWORD=<password>
SCA_TOTP_SECRET=<base32 TOTP secret>
SCA_TOTP_ISSUER=CyberIAM
SCA_TOTP_DIGITS=6
SCA_TOTP_ALGORITHM=SHA1
SCA_TOTP_PERIOD=30
SCA_IDENTITY_URL=https://<tenant>.id.cyberark.cloud
```

## Run

```bash
cd poc
go run .
```

## Run Tests

```bash
cd poc
go test -v ./...
```

## How It Works

1. **`totp.go`** - Generates 6-digit TOTP codes from the secret using `pquerna/otp` (SHA1, 30s period)
2. **`auth.go`** - Replicates the `IdsecIdentity` auth flow from `idsec-sdk-golang` without interactive prompts:
   - `POST /Security/StartAuthentication` (username)
   - `POST /Security/AdvanceAuthentication` (password, UP mechanism)
   - `POST /Security/AdvanceAuthentication` (StartOOB, OATH mechanism)
   - `POST /Security/AdvanceAuthentication` (TOTP code, OATH mechanism)
3. **`main.go`** - Uses the JWT to call SCA Access API endpoints across multiple service URL patterns:
   - `{subdomain}.sca.{domain}` (SDK pattern)
   - `{subdomain}.{domain}` (no service prefix)
   - `{subdomain}.access.{domain}` (alternative)
   - `{subdomain}-sca.{domain}` (dash separator)

All responses are logged as raw JSON for analysis.

## Architecture Notes

- Does **not** use the SDK's `IdsecISPAuth` or `IdsecIdentity` directly (those require `survey/v2` interactive prompts)
- Instead, replicates the HTTP calls from `idsec-sdk-golang v0.1.14` (`pkg/auth/identity/idsec_identity.go`)
- Auth flow matches the SDK exactly: `StartAuthentication` -> `AdvanceAuthentication(UP)` -> `AdvanceAuthentication(StartOOB for OATH)` -> `AdvanceAuthentication(OATH answer)`
- PoC-only dependencies: `pquerna/otp` (TOTP), `joho/godotenv` (.env loading)
