async def m001_initial(db):
    await db.execute(
        """
        CREATE TABLE tagid.cards (
            id TEXT PRIMARY KEY UNIQUE,
            wallet TEXT NOT NULL,
            card_name TEXT NOT NULL,
            uid TEXT NOT NULL UNIQUE,
            external_id TEXT NOT NULL UNIQUE,
            counter INT NOT NULL DEFAULT 0,
            tx_limit TEXT NOT NULL,
            daily_limit TEXT NOT NULL,
            enable BOOL NOT NULL,
            k0 TEXT NOT NULL DEFAULT '00000000000000000000000000000000',
            k1 TEXT NOT NULL DEFAULT '00000000000000000000000000000000',
            k2 TEXT NOT NULL DEFAULT '00000000000000000000000000000000',
            prev_k0 TEXT NOT NULL DEFAULT '00000000000000000000000000000000',
            prev_k1 TEXT NOT NULL DEFAULT '00000000000000000000000000000000',
            prev_k2 TEXT NOT NULL DEFAULT '00000000000000000000000000000000',
            otp TEXT NOT NULL DEFAULT '',
            time TIMESTAMP NOT NULL DEFAULT """
        + db.timestamp_now
        + """
        );
    """
    )

    await db.execute(
        f"""
        CREATE TABLE tagid.hits (
            id TEXT PRIMARY KEY UNIQUE,
            card_id TEXT NOT NULL,
            ip TEXT NOT NULL,
            spent BOOL NOT NULL DEFAULT True,
            useragent TEXT,
            old_ctr INT NOT NULL DEFAULT 0,
            new_ctr INT NOT NULL DEFAULT 0,
            amount {db.big_int} NOT NULL,
            time TIMESTAMP NOT NULL DEFAULT """
        + db.timestamp_now
        + """
        );
    """
    )

    await db.execute(
        f"""
        CREATE TABLE tagid.refunds (
            id TEXT PRIMARY KEY UNIQUE,
            hit_id TEXT NOT NULL,
            refund_amount {db.big_int} NOT NULL,
            time TIMESTAMP NOT NULL DEFAULT """
        + db.timestamp_now
        + """
        );
    """
    )


async def m002_correct_typing(db):
    await db.execute("ALTER TABLE tagid.cards RENAME TO cards_m001;")
    await db.execute(
        """
        CREATE TABLE tagid.cards (
            id TEXT PRIMARY KEY UNIQUE,
            wallet TEXT NOT NULL,
            card_name TEXT NOT NULL,
            uid TEXT NOT NULL UNIQUE,
            external_id TEXT NOT NULL UNIQUE,
            counter INT NOT NULL DEFAULT 0,
            tx_limit INT NOT NULL,
            daily_limit INT NOT NULL,
            enable BOOL NOT NULL,
            k0 TEXT NOT NULL DEFAULT '00000000000000000000000000000000',
            k1 TEXT NOT NULL DEFAULT '00000000000000000000000000000000',
            k2 TEXT NOT NULL DEFAULT '00000000000000000000000000000000',
            prev_k0 TEXT NOT NULL DEFAULT '00000000000000000000000000000000',
            prev_k1 TEXT NOT NULL DEFAULT '00000000000000000000000000000000',
            prev_k2 TEXT NOT NULL DEFAULT '00000000000000000000000000000000',
            otp TEXT NOT NULL DEFAULT '',
            time TIMESTAMP NOT NULL DEFAULT """
        + db.timestamp_now
        + """
        );
    """
    )

    await db.execute(
        """
        INSERT INTO tagid.cards (
            id,
            wallet,
            card_name,
            uid,
            external_id,
            counter,
            tx_limit,
            daily_limit,
            enable,
            k0,
            k1,
            k2,
            prev_k0,
            prev_k1,
            prev_k2,
            otp,
            time
        )
        SELECT
            id,
            wallet,
            card_name,
            uid,
            external_id,
            counter,
            CAST(tx_limit AS INT),
            CAST(daily_limit AS INT),
            enable,
            k0,
            k1,
            k2,
            prev_k0,
            prev_k1,
            prev_k2,
            otp,
            time
        FROM tagid.cards_m001;
    """
    )
    await db.execute("DROP TABLE tagid.cards_m001;")


async def _columns(db, table: str) -> set[str]:
    # Works on SQLite and Postgres, also for empty tables (column metadata only).
    result = await db.execute(f"SELECT * FROM {table} LIMIT 1")
    return set(result.keys())


async def _add_column(db, table: str, column: str, ddl: str) -> None:
    """Add a column only if it is missing.

    Replaces the earlier try/except-pass pattern: on Postgres a failed ALTER
    aborts the surrounding transaction, so every later statement would fail.
    """
    if column not in await _columns(db, table):
        await db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


async def m003_add_pin_limit(db):
    await _add_column(db, "tagid.cards", "pin_limit", "INT DEFAULT NULL")
    await _add_column(db, "tagid.cards", "pin", "TEXT DEFAULT NULL")
    await _add_column(db, "tagid.hits", "pin_attempts", "INT NOT NULL DEFAULT 0")


async def m004_add_pin_blocked(db):
    # Column is no longer used (blocking disables the card), kept for history.
    await _add_column(db, "tagid.cards", "pin_blocked", "BOOL NOT NULL DEFAULT FALSE")


async def m005_add_card_pin_attempts(db):
    await _add_column(db, "tagid.cards", "pin_total_attempts", "INT NOT NULL DEFAULT 0")


async def m006_zapbox_verify(db):
    # No schema change — marker that bumps the migration sequence to v2.1.0.
    pass


async def m007_claims(db):
    """Per-claim accounting from boltcards v1.2.0 (m003_claims there), plus
    a repair step for the PIN columns.

    amount_msat / claimed_at drive the daily budget in SQL (UTC day),
    max_msat is the withdrawable amount fixed when the hit was created
    (0 for verify-only hits, so they can never be paid out).
    """
    # Before v2.2.0, m002 was defined after m003-m006 in this file and LNbits
    # runs migrations in definition order: on a fresh install m002 rebuilt
    # tagid.cards and dropped the PIN columns again. Re-add them if missing.
    await m003_add_pin_limit(db)
    await m005_add_card_pin_attempts(db)

    await _add_column(
        db, "tagid.hits", "amount_msat", f"{db.big_int} NOT NULL DEFAULT 0"
    )
    await _add_column(db, "tagid.hits", "max_msat", f"{db.big_int} NOT NULL DEFAULT 0")
    await _add_column(db, "tagid.hits", "claimed_at", "TIMESTAMP")
    await db.execute(
        "UPDATE tagid.hits SET amount_msat = amount * 1000, claimed_at = time "
        "WHERE spent = TRUE AND claimed_at IS NULL"
    )
    # Open (unspent) hits from before this version — verify-only taps and
    # abandoned withdraw requests — get no withdraw budget (max_msat stays 0)
    # and are closed. A fresh tap creates a new hit anyway.
    await db.execute("UPDATE tagid.hits SET spent = TRUE WHERE spent = FALSE")
