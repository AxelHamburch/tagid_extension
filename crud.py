import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from hashlib import pbkdf2_hmac

from lnbits.db import Connection, Database, model_to_dict, update_query
from lnbits.helpers import urlsafe_short_hash
from loguru import logger
from sqlalchemy import text

from .models import Card, CreateCardData, Hit, Refund

db = Database("ext_tagid")

MAX_PIN_ATTEMPTS = 3


def hash_pin(pin: str, card_id: str) -> str:
    return pbkdf2_hmac("sha256", pin.encode(), card_id.encode(), 100_000, 32).hex()


def verify_pin(pin: str, card_id: str, stored_hash: str) -> bool:
    return secrets.compare_digest(hash_pin(pin, card_id), stored_hash)


class PinError(ValueError):
    """Wrong or missing PIN. The message is shown to the payer/device.

    Messages are part of the protocol with zapbox_extension: it checks for
    the word "blocked" to stop its PIN retry loop.
    """


async def create_card(data: CreateCardData, wallet_id: str) -> Card:
    card_id = urlsafe_short_hash().upper()
    extenal_id = urlsafe_short_hash().lower()

    hashed_pin = hash_pin(data.pin, card_id) if data.pin else None

    await db.execute(
        """
        INSERT INTO tagid.cards (
            id,
            uid,
            external_id,
            wallet,
            card_name,
            counter,
            tx_limit,
            daily_limit,
            enable,
            k0,
            k1,
            k2,
            otp,
            pin_limit,
            pin
        )
        VALUES (
            :id, :uid, :external_id, :wallet, :card_name, :counter,
            :tx_limit, :daily_limit, :enable, :k0, :k1, :k2, :otp,
            :pin_limit, :pin
        )
        """,
        {
            "id": card_id,
            "uid": data.uid.upper(),
            "external_id": extenal_id,
            "wallet": wallet_id,
            "card_name": data.card_name,
            "counter": data.counter,
            "tx_limit": data.tx_limit,
            "daily_limit": data.daily_limit,
            "enable": True,
            "k0": data.k0,
            "k1": data.k1,
            "k2": data.k2,
            "otp": secrets.token_hex(16),
            "pin_limit": data.pin_limit,
            "pin": hashed_pin,
        },
    )
    card = await get_card(card_id)
    assert card, "Newly created card couldn't be retrieved"
    return card


async def update_card(card: Card) -> Card:
    async with _card_transaction(card.id) as conn:
        previous = await conn.fetchone(
            "SELECT * FROM tagid.cards WHERE id = :id", {"id": card.id}, Card
        )
        keys_changed = previous is not None and (
            previous.uid.upper() != card.uid.upper()
            or bytes.fromhex(previous.k1) != bytes.fromhex(card.k1)
            or bytes.fromhex(previous.k2) != bytes.fromhex(card.k2)
        )
        if previous and not keys_changed:
            # Never move the counter backwards: that would re-enable old taps.
            card.counter = max(card.counter, previous.counter)
        card.otp = secrets.token_hex(16)
        await conn.conn.execute(
            text(update_query("tagid.cards", card)), model_to_dict(card)
        )
        if previous and (not card.enable or keys_changed):
            await _close_open_hits(conn, card.id)
    return card


async def get_cards(wallet_ids: list[str]) -> list[Card]:
    if len(wallet_ids) == 0:
        return []
    q = ",".join([f"'{wallet_id}'" for wallet_id in wallet_ids])
    return await db.fetchall(
        f"SELECT * FROM tagid.cards WHERE wallet IN ({q})",
        model=Card,
    )


async def get_card(card_id: str) -> Card | None:
    return await db.fetchone(
        "SELECT * FROM tagid.cards WHERE id = :id",
        {"id": card_id},
        Card,
    )


async def get_card_by_uid(card_uid: str, wallet_id: str) -> Card | None:
    return await db.fetchone(
        "SELECT * FROM tagid.cards WHERE uid = :uid AND wallet = :wallet",
        {"uid": card_uid.upper(), "wallet": wallet_id},
        Card,
    )


async def get_card_by_external_id(external_id: str) -> Card | None:
    return await db.fetchone(
        "SELECT * FROM tagid.cards WHERE external_id = :ext_id",
        {"ext_id": external_id.lower()},
        Card,
    )


async def delete_card(card_id: str) -> None:
    # Delete cards
    await db.execute("DELETE FROM tagid.cards WHERE id = :id", {"id": card_id})
    # Delete hits
    hits = await get_hits([card_id])
    for hit in hits:
        await db.execute("DELETE FROM tagid.hits WHERE id = :id", {"id": hit.id})
        # Delete refunds
        refunds = await get_refunds([hit.id])
        for refund in refunds:
            await db.execute(
                "DELETE FROM tagid.refunds WHERE id = :id", {"id": refund.id}
            )


async def enable_disable_card(enable: bool, card_id: str) -> Card | None:
    async with _card_transaction(card_id) as conn:
        card = await conn.fetchone(
            "SELECT * FROM tagid.cards WHERE id = :id", {"id": card_id}, Card
        )
        if not card:
            return None
        if enable and not all((card.k0, card.k1, card.k2)):
            raise ValueError("Re-provision the card before enabling it.")
        if enable:
            # Reset the PIN failure counter when the owner re-enables the card,
            # so the first wrong PIN does not immediately block it again.
            await conn.conn.execute(
                text(
                    "UPDATE tagid.cards SET enable = TRUE, pin_total_attempts = 0 "
                    "WHERE id = :id"
                ),
                {"id": card_id},
            )
            card.pin_total_attempts = 0
        else:
            await conn.conn.execute(
                text("UPDATE tagid.cards SET enable = FALSE WHERE id = :id"),
                {"id": card_id},
            )
            await _close_open_hits(conn, card_id)
        card.enable = enable
        return card


async def consume_card_otp(
    otp: str, wipe: bool = False, uid: str | None = None
) -> Card | None:
    if len(otp) != 32:
        return None
    card = await db.fetchone(
        "SELECT * FROM tagid.cards WHERE otp = :otp", {"otp": otp}, Card
    )
    if not card:
        return None
    async with _card_transaction(card.id) as conn:
        card = await conn.fetchone(
            "SELECT * FROM tagid.cards WHERE id = :id AND otp = :otp",
            {"id": card.id, "otp": otp},
            Card,
        )
        if not card or (uid and uid.upper() != card.uid.upper()):
            return None
        if not all((card.k0, card.k1, card.k2)):
            return None
        changes = "otp = :new_otp"
        if wipe:
            # A wiped card is "new": keys and PIN settings are removed.
            changes += (
                ", enable = FALSE, k0 = '', k1 = '', k2 = '', "
                "prev_k0 = '', prev_k1 = '', prev_k2 = '', "
                "pin = NULL, pin_limit = NULL, pin_total_attempts = 0"
            )
        result = await conn.conn.execute(
            text(f"UPDATE tagid.cards SET {changes} WHERE id = :id AND otp = :otp"),
            {"id": card.id, "otp": otp, "new_otp": secrets.token_hex(16)},
        )
        if result.rowcount != 1:
            return None
        if wipe:
            await _close_open_hits(conn, card.id)
        logger.info("TagID auth redeemed: {} (wipe={})", card.id, wipe)
        return card


async def get_hit(hit_id: str) -> Hit | None:
    return await db.fetchone(
        "SELECT * FROM tagid.hits WHERE id = :id",
        {"id": hit_id},
        Hit,
    )


async def get_hits(cards_ids: list[str]) -> list[Hit]:
    if len(cards_ids) == 0:
        return []

    q = ",".join([f"'{card_id}'" for card_id in cards_ids])
    return await db.fetchall(
        f"SELECT * FROM tagid.hits WHERE card_id IN ({q})",
        model=Hit,
    )


async def create_hit(
    card: Card, ip: str, useragent: str, new_ctr: int, payable: bool = True
) -> Hit:
    """Atomically advance the card counter and record the tap.

    `payable=False` is used by the verify-only endpoint (ZapBox Ring-Login):
    the hit gets max_msat = 0 and is stored as spent, so it can never be
    redeemed for a withdrawal.
    """
    async with _card_transaction(card.id) as conn:
        current = await conn.fetchone(
            "SELECT * FROM tagid.cards WHERE id = :id", {"id": card.id}, Card
        )
        if not current or not current.enable:
            raise ValueError("Card is disabled.")
        if (current.uid, current.k1, current.k2) != (card.uid, card.k1, card.k2):
            raise ValueError("Card has changed. Please tap again.")
        if payable:
            max_msat = min(
                current.tx_limit * 1000, await _remaining_budget(conn, current)
            )
            if max_msat < 1000:
                max_msat = 0
        else:
            max_msat = 0
        result = await conn.conn.execute(
            text(
                "UPDATE tagid.cards SET counter = :counter "
                "WHERE id = :id AND counter < :counter AND enable = TRUE"
            ),
            {"counter": new_ctr, "id": card.id},
        )
        if result.rowcount != 1:
            raise ValueError("This link is already used.")
        hit_id = secrets.token_hex(16)
        await conn.conn.execute(
            text(
                """
                INSERT INTO tagid.hits
                (id, card_id, ip, spent, useragent, old_ctr, new_ctr, amount, max_msat)
                VALUES (:id, :card_id, :ip, :spent, :agent,
                        :old_ctr, :new_ctr, 0, :max_msat)
            """
            ),
            {
                "id": hit_id,
                "card_id": card.id,
                "ip": ip,
                "spent": not payable,
                "agent": useragent,
                "old_ctr": current.counter,
                "new_ctr": new_ctr,
                "max_msat": max_msat,
            },
        )
        return await conn.fetchone(
            "SELECT * FROM tagid.hits WHERE id = :id", {"id": hit_id}, Hit
        )


async def spend_hit(
    hit_id: str, amount_msat: int, pin: str | None = None
) -> tuple[Hit, Card]:
    """Claim a withdraw hit. PIN check and spend happen in one card transaction,
    so parallel requests cannot get more than MAX_PIN_ATTEMPTS guesses.

    A wrong PIN does NOT consume the hit: the ZapBox PIN loop retries the same
    k1 up to three times. Raises PinError for PIN problems (after committing
    the attempt counters) and ValueError for everything else.
    """
    hit = await get_hit(hit_id)
    if not hit:
        raise ValueError("LNURL-withdraw record not found.")
    pin_error: str | None = None
    async with _card_transaction(hit.card_id) as conn:
        card = await conn.fetchone(
            "SELECT * FROM tagid.cards WHERE id = :id", {"id": hit.card_id}, Card
        )
        hit = await conn.fetchone(
            "SELECT * FROM tagid.hits WHERE id = :id", {"id": hit_id}, Hit
        )
        if not card or not card.enable:
            raise ValueError("Card is disabled.")
        if not hit or hit.spent:
            raise ValueError("Payment already claimed.")
        now = datetime.now(timezone.utc)
        remaining = await _remaining_budget(conn, card, now)
        if (
            not 1000
            <= amount_msat
            <= min(hit.max_msat, card.tx_limit * 1000, remaining)
        ):
            raise ValueError("Invoice exceeds the available withdrawal limit.")

        if card.pin_limit is not None and amount_msat >= card.pin_limit * 1000:
            if not pin:
                raise PinError("PIN required.")
            if card.pin and verify_pin(pin, card.id, card.pin):
                await conn.conn.execute(
                    text(
                        "UPDATE tagid.cards SET pin_total_attempts = 0 WHERE id = :id"
                    ),
                    {"id": card.id},
                )
            else:
                pin_error = await _register_wrong_pin(conn, card, hit.id)

        if pin_error is None:
            result = await conn.conn.execute(
                text(
                    f"""
                    UPDATE tagid.hits
                    SET spent = TRUE, amount = :amount, amount_msat = :amount_msat,
                        claimed_at = {db.timestamp_placeholder('claimed_at')}
                    WHERE id = :id AND spent = FALSE
                """
                ),
                {
                    "id": hit.id,
                    "amount": (amount_msat + 999) // 1000,
                    "amount_msat": amount_msat,
                    "claimed_at": now.timestamp(),
                },
            )
            if result.rowcount != 1:
                raise ValueError("Payment already claimed.")
            hit.spent = True
            hit.amount = (amount_msat + 999) // 1000
            hit.amount_msat = amount_msat
            hit.claimed_at = now
    # Raised outside the transaction so the attempt counters are committed.
    if pin_error:
        raise PinError(pin_error)
    return hit, card


async def check_card_pin(card_id: str, pin: str) -> None:
    """PIN check for the verify-only endpoint. Same counters and blocking rules
    as payments. Raises PinError on a wrong PIN (counters committed)."""
    pin_error: str | None = None
    async with _card_transaction(card_id) as conn:
        card = await conn.fetchone(
            "SELECT * FROM tagid.cards WHERE id = :id", {"id": card_id}, Card
        )
        if not card or not card.enable:
            raise ValueError("Card is disabled.")
        if card.pin and verify_pin(pin, card.id, card.pin):
            await conn.conn.execute(
                text("UPDATE tagid.cards SET pin_total_attempts = 0 WHERE id = :id"),
                {"id": card.id},
            )
        else:
            pin_error = await _register_wrong_pin(conn, card, None)
    if pin_error:
        raise PinError(pin_error)


async def release_hit(hit_id: str) -> None:
    # A failed claim stays consumed, so the same bearer token cannot be retried.
    await db.execute(
        "UPDATE tagid.hits SET amount = 0, amount_msat = 0 WHERE id = :id",
        {"id": hit_id},
    )


async def create_refund(hit_id, refund_amount) -> Refund:
    refund_id = urlsafe_short_hash()
    await db.execute(
        """
        INSERT INTO tagid.refunds (
            id,
            hit_id,
            refund_amount
        )
        VALUES (:id, :hit_id, :refund_amount)
        """,
        {
            "id": refund_id,
            "hit_id": hit_id,
            "refund_amount": refund_amount,
        },
    )
    refund = await get_refund(refund_id)
    assert refund, "Newly recorded hit couldn't be retrieved"
    return refund


async def get_refund(refund_id: str) -> Refund | None:
    return await db.fetchone(
        "SELECT * FROM tagid.refunds WHERE id = :id",
        {"id": refund_id},
        Refund,
    )


async def get_refunds(hits_ids: list[str]) -> list[Refund]:
    if len(hits_ids) == 0:
        return []
    q = ",".join([f"'{hit_id}'" for hit_id in hits_ids])
    return await db.fetchall(
        f"SELECT * FROM tagid.refunds WHERE hit_id IN ({q})",
        model=Refund,
    )


async def _register_wrong_pin(conn: Connection, card: Card, hit_id: str | None) -> str:
    """Count a wrong PIN inside the caller's card transaction.

    Returns the error message. At MAX_PIN_ATTEMPTS the card is disabled and
    all open hits are closed.
    """
    total = card.pin_total_attempts + 1
    await conn.conn.execute(
        text("UPDATE tagid.cards SET pin_total_attempts = :total WHERE id = :id"),
        {"total": total, "id": card.id},
    )
    if hit_id:
        await conn.conn.execute(
            text(
                "UPDATE tagid.hits SET pin_attempts = pin_attempts + 1 WHERE id = :id"
            ),
            {"id": hit_id},
        )
    if total >= MAX_PIN_ATTEMPTS:
        await conn.conn.execute(
            text("UPDATE tagid.cards SET enable = FALSE WHERE id = :id"),
            {"id": card.id},
        )
        await _close_open_hits(conn, card.id)
        logger.warning("TagID card blocked after {} wrong PINs: {}", total, card.id)
        return "Card blocked: too many incorrect PIN attempts."
    return f"Invalid PIN. {MAX_PIN_ATTEMPTS - total} attempt(s) remaining."


async def _close_open_hits(conn: Connection, card_id: str) -> None:
    await conn.conn.execute(
        text(
            "UPDATE tagid.hits SET spent = TRUE WHERE card_id = :id AND spent = FALSE"
        ),
        {"id": card_id},
    )


@asynccontextmanager
async def _card_transaction(card_id: str) -> AsyncIterator[Connection]:
    async with db.connect() as conn:
        # Connection.execute commits; keep these writes in one transaction.
        async with conn.conn.begin():
            # Lock before reading; this also serializes SQLite writers.
            await conn.conn.execute(
                text("UPDATE tagid.cards SET counter = counter WHERE id = :id"),
                {"id": card_id},
            )
            yield conn


async def _remaining_budget(
    conn: Connection, card: Card, now: datetime | None = None
) -> int:
    now = now or datetime.now(timezone.utc)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=1)
    row: dict = await conn.fetchone(
        f"""
            SELECT COALESCE(SUM(amount_msat), 0) AS total FROM tagid.hits
            WHERE card_id = :id AND claimed_at >= {db.timestamp_placeholder('start')}
              AND claimed_at < {db.timestamp_placeholder('end')}
        """,
        {"id": card.id, "start": start.timestamp(), "end": end.timestamp()},
    )
    return card.daily_limit * 1000 - int(row["total"])
