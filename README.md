# TagID Extension - <small>[LNbits](https://github.com/lnbits/lnbits) extension</small>

> **Forked from [lnbits/boltcards](https://github.com/lnbits/boltcards)**  
> Extended with PIN limit protection and failed-payment daily-limit fix.

Self custody NFC Bolt Cards with one-time LNURLw links — now with optional PIN verification and accurate daily spend tracking.

Check out [lnbits.com](https://lnbits.com) & join the Telegram support group [Makerbits](https://t.me/makerbits)

`Original authors: dni, prusnak, talvasconcelos, arbadacarbaYK, gorrdy, arcbtc` / `TagID extension: AxelHamburch`

Extension manifest source for LNbits: [https://raw.githubusercontent.com/AxelHamburch/tagid_extension/main/extensions.json](https://raw.githubusercontent.com/AxelHamburch/tagid_extension/main/extensions.json)

> **LNbits 1.7.x:** use `extensions.json` as manifest URL. The older `manifest.json` (GitHub-repo format) does not list any extension in LNbits 1.7.0/1.7.1, because core fails to parse the GitHub API answer (`stargazers_count` is declared as `str`, GitHub returns a number).

---

## v2.2.0 – Security update for LNbits 1.7.0 (breaking)

Requires **LNbits 1.7.0** or newer. Based on the security hardening of upstream boltcards v1.2.1, plus TagID-specific fixes.

**Security fixes**

- Card keys (K0–K2) are only handed out against a valid one-time programming link (OTP) and matching UID. Before, the UID alone was enough.
- Withdrawals are atomic: a tap and a claim can only be used once, also under parallel requests. Daily limit and transaction limit are checked in the database before paying (UTC day).
- PIN checks happen in the same database transaction as the payment, so parallel requests cannot get more than 3 PIN guesses. A wrong PIN does not consume the tap.
- The PIN failure counter is only reset by a correct PIN or by re-enabling the card. Small payments below the PIN limit no longer reset it.
- The PIN hash is no longer part of any API response (`has_pin: true/false` instead).
- Refunds are only accepted for payments into the card's own wallet.
- Rate limits on the programming endpoint (10/min per IP) and on the verify endpoint (10/min per card).
- Verify-only taps (ZapBox Ring-Login) can never be paid out.
- Wiping a card also removes its PIN and PIN limit.

**Breaking changes**

- `GET /tagid/api/v1/cards`, `/hits` and `/refunds` require the wallet **admin key** (was: invoice key).
- API responses no longer contain `pin`; use `has_pin`.
- Programming via `POST /tagid/api/v1/auth` needs the OTP from the QR code, the UID alone is rejected. The Bolt Card Programmer app does this automatically.
- `GET /tagid/api/v1/scan/verify/{external_id}` returns an additional field `pin_verified`. A PIN sent for a card without PIN is ignored (no failed attempt).
- Open withdraw requests from before the update are closed during migration. Simply tap the card again.

---

## Added Features

### PIN Limit (optional per-card PIN protection)

- Set a **PIN threshold (sat)**: any withdrawal at or above this amount requires the card holder to enter a 4-digit PIN.
- The PIN is stored as a salted PBKDF2-SHA256 hash — never in plaintext.
- After **3 wrong PIN attempts** across taps the card is automatically **disabled** and must be re-enabled by the wallet owner.
- Attempt counter resets when the card is re-enabled or when a correct PIN is entered.

### Failed-Payment Daily Limit Fix

- Limit checks (tx limit & daily limit) now happen **before** the hit is marked as spent, so a rejected payment does not consume the daily budget.
- When a payment fails after the invoice was accepted, the hit amount is zeroed so it does not count towards the daily limit.
