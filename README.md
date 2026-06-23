# TagID Extension - <small>[LNbits](https://github.com/lnbits/lnbits) extension</small>

> **Forked from [lnbits/boltcards](https://github.com/lnbits/boltcards)**  
> Extended with PIN limit protection and failed-payment daily-limit fix.

Self custody NFC Bolt Cards with one-time LNURLw links — now with optional PIN verification and accurate daily spend tracking.

Check out [lnbits.com](https://lnbits.com) & join the Telegram support group [Makerbits](https://t.me/makerbits)

`Original authors: dni, prusnak, talvasconcelos, arbadacarbaYK, gorrdy, arcbtc` / `TagID extension: AxelHamburch`

Extension manifest source for LNbits: [https://raw.githubusercontent.com/AxelHamburch/tagid_extension/main/manifest.json](https://raw.githubusercontent.com/AxelHamburch/tagid_extension/main/manifest.json)

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
