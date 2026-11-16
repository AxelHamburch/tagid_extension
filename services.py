import bolt11
from lnbits.core.services import pay_invoice
from lnbits.exceptions import PaymentError
from loguru import logger

from .crud import (
    PinError,
    create_hit,
    get_card_by_external_id,
    get_hit,
    release_hit,
    spend_hit,
)
from .models import Card, Hit
from .nxp424 import decrypt_sun, get_sun_mac


class CardAuthError(ValueError):
    """SUN/CMAC verification failed (wrong card, forged or malformed tap)."""


class CardNotFoundError(ValueError):
    pass


class CardDisabledError(ValueError):
    pass


async def authenticate_tap(external_id: str, p: str, c: str) -> tuple[Card, int]:
    """Check the SUN message of a tap. Returns the card and the tap counter.

    Does not touch the database; the counter is advanced by create_hit().
    """
    card = await get_card_by_external_id(external_id)
    if not card:
        raise CardNotFoundError("Card not found.")
    if not card.enable:
        raise CardDisabledError("Card is disabled.")
    try:
        card_uid, counter = decrypt_sun(bytes.fromhex(p), bytes.fromhex(card.k1))
        expected_mac = get_sun_mac(card_uid, counter, bytes.fromhex(card.k2))
    except Exception as exc:
        raise CardAuthError("Error decrypting card.") from exc
    if card.uid.upper() != card_uid.hex().upper():
        raise CardAuthError("Card UID mis-match.")
    if c.upper() != expected_mac.hex().upper():
        raise CardAuthError("CMAC does not check.")
    return card, int.from_bytes(counter, "little")


async def scan_card(
    external_id: str, p: str, c: str, ip: str, useragent: str
) -> tuple[Hit, Card]:
    card, counter = await authenticate_tap(external_id, p, c)
    hit = await create_hit(card, ip, useragent, counter)
    return hit, card


async def pay_card_invoice(
    hit_id: str, payment_request: str | None, pin: str | None = None
) -> None:
    hit = await get_hit(hit_id)
    if not hit:
        raise ValueError("LNURL-withdraw record not found.")
    if hit.spent:
        raise ValueError("Payment already claimed.")
    if not payment_request:
        raise ValueError("Missing payment request.")
    try:
        invoice = bolt11.decode(payment_request)
    except bolt11.Bolt11Exception as exc:
        raise ValueError("Failed to decode payment request.") from exc
    if not invoice.amount_msat:
        raise ValueError("Invoice has no amount.")
    # Raises PinError (hit stays open for another PIN attempt) or ValueError.
    hit, card = await spend_hit(hit.id, int(invoice.amount_msat), pin)
    try:
        await pay_invoice(
            wallet_id=card.wallet,
            payment_request=payment_request,
            max_sat=card.tx_limit,
            extra={"tag": "tagid", "hit": hit.id},
        )
    except PaymentError as exc:
        if exc.status == "failed":
            await release_hit(hit.id)
        raise ValueError("Payment failed or is still pending.") from exc
    except Exception as exc:
        # shortcut: unknown outcomes keep their allowance until UTC midnight;
        # reconcile payment status to release it sooner.
        logger.warning("TagID payment outcome unknown: {}", hit.id)
        raise ValueError("Payment failed or is still pending.") from exc


__all__ = [
    "CardAuthError",
    "CardDisabledError",
    "CardNotFoundError",
    "PinError",
    "authenticate_tap",
    "pay_card_invoice",
    "scan_card",
]
