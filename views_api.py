from http import HTTPStatus

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from lnbits.core.crud import get_user
from lnbits.core.models import WalletTypeInfo
from lnbits.decorators import require_admin_key, require_invoice_key

from .crud import (
    create_card,
    create_hit,
    delete_card,
    enable_disable_card,
    get_card,
    get_card_by_external_id,
    get_card_by_uid,
    get_cards,
    get_hits,
    get_refunds,
    hash_pin,
    increment_card_pin_attempts,
    reset_card_pin_attempts,
    update_card,
    update_card_counter,
    verify_pin,
)
from .models import Card, CreateCardData, Hit, Refund
from .nxp424 import decrypt_sun, get_sun_mac

tagid_api_router = APIRouter()


@tagid_api_router.get("/api/v1/cards")
async def api_cards(
    key_info: WalletTypeInfo = Depends(require_invoice_key), all_wallets: bool = False
) -> list[Card]:
    wallet_ids = [key_info.wallet.id]

    if all_wallets:
        user = await get_user(key_info.wallet.user)
        wallet_ids = user.wallet_ids if user else []

    return await get_cards(wallet_ids)


def validate_card(data: CreateCardData):
    try:
        if len(bytes.fromhex(data.uid)) != 7:
            raise HTTPException(
                detail="Invalid bytes for card uid.", status_code=HTTPStatus.BAD_REQUEST
            )

        if len(bytes.fromhex(data.k0)) != 16:
            raise HTTPException(
                detail="Invalid bytes for k0.", status_code=HTTPStatus.BAD_REQUEST
            )

        if len(bytes.fromhex(data.k1)) != 16:
            raise HTTPException(
                detail="Invalid bytes for k1.", status_code=HTTPStatus.BAD_REQUEST
            )

        if len(bytes.fromhex(data.k2)) != 16:
            raise HTTPException(
                detail="Invalid bytes for k2.", status_code=HTTPStatus.BAD_REQUEST
            )
    except Exception as exc:
        raise HTTPException(
            detail="Invalid byte data provided.", status_code=HTTPStatus.BAD_REQUEST
        ) from exc


@tagid_api_router.put(
    "/api/v1/cards/{card_id}",
    status_code=HTTPStatus.OK,
    dependencies=[Depends(validate_card)],
)
async def api_card_update(
    data: CreateCardData,
    card_id: str,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> Card:
    card = await get_card(card_id)
    if not card:
        raise HTTPException(
            detail="Card does not exist.", status_code=HTTPStatus.NOT_FOUND
        )
    if card.wallet != wallet.wallet.id:
        raise HTTPException(detail="Not your card.", status_code=HTTPStatus.FORBIDDEN)
    check_uid = await get_card_by_uid(data.uid)
    if check_uid and check_uid.id != card_id:
        raise HTTPException(
            detail="UID already registered. Delete registered card and try again.",
            status_code=HTTPStatus.BAD_REQUEST,
        )
    for key, value in data.dict().items():
        setattr(card, key, value)
    if data.pin:
        card.pin = hash_pin(data.pin, card.id)
        card.pin_total_attempts = 0
    elif data.pin is None:
        card.pin = None
        card.pin_total_attempts = 0
    await update_card(card)
    return card


@tagid_api_router.post(
    "/api/v1/cards",
    status_code=HTTPStatus.CREATED,
    dependencies=[Depends(validate_card)],
)
async def api_card_create(
    data: CreateCardData,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> Card:
    check_uid = await get_card_by_uid(data.uid)
    if check_uid:
        raise HTTPException(
            detail="UID already registered. Delete registered card and try again.",
            status_code=HTTPStatus.BAD_REQUEST,
        )
    card = await create_card(wallet_id=wallet.wallet.id, data=data)
    if not card:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Could not create card.",
        )
    return card


@tagid_api_router.get(
    "/api/v1/cards/enable/{card_id}/{enable}", status_code=HTTPStatus.OK
)
async def enable_card(
    card_id: str,
    enable: bool,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> Card:
    card = await get_card(card_id)
    if not card:
        raise HTTPException(detail="No card found.", status_code=HTTPStatus.NOT_FOUND)
    if card.wallet != wallet.wallet.id:
        raise HTTPException(detail="Not your card.", status_code=HTTPStatus.FORBIDDEN)
    card = await enable_disable_card(enable=enable, card_id=card_id)
    if not card:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Could not update card.",
        )
    return card


@tagid_api_router.delete("/api/v1/cards/{card_id}")
async def api_card_delete(
    card_id, wallet: WalletTypeInfo = Depends(require_admin_key)
) -> None:
    card = await get_card(card_id)

    if not card:
        raise HTTPException(
            detail="Card does not exist.", status_code=HTTPStatus.NOT_FOUND
        )

    if card.wallet != wallet.wallet.id:
        raise HTTPException(detail="Not your card.", status_code=HTTPStatus.FORBIDDEN)

    await delete_card(card_id)


@tagid_api_router.get("/api/v1/hits")
async def api_hits(
    key_info: WalletTypeInfo = Depends(require_invoice_key),
    all_wallets: bool = Query(False),
) -> list[Hit]:
    wallet_ids = [key_info.wallet.id]

    if all_wallets:
        user = await get_user(key_info.wallet.user)
        wallet_ids = user.wallet_ids if user else []

    cards = await get_cards(wallet_ids)
    cards_ids = []
    for card in cards:
        cards_ids.append(card.id)

    return await get_hits(cards_ids)


@tagid_api_router.get("/api/v1/scan/verify/{external_id}")
async def api_scan_verify(
    external_id: str,
    p: str = Query(...),
    c: str = Query(...),
    pin: str | None = Query(None),
    request: Request = None,
    wallet: WalletTypeInfo = Depends(require_invoice_key),
) -> dict:
    p = p.upper()
    c = c.upper()

    card = await get_card_by_external_id(external_id)
    if not card:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Card not found.")
    if not card.enable:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Card is disabled.")

    try:
        card_uid, counter = decrypt_sun(bytes.fromhex(p), bytes.fromhex(card.k1))
        if card.uid.upper() != card_uid.hex().upper():
            raise HTTPException(
                status_code=HTTPStatus.FORBIDDEN, detail="Card UID mismatch."
            )
        if c != get_sun_mac(card_uid, counter, bytes.fromhex(card.k2)).hex().upper():
            raise HTTPException(
                status_code=HTTPStatus.FORBIDDEN, detail="CMAC does not check."
            )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="Error decrypting card."
        )

    ctr_int = int.from_bytes(counter, "little")
    if ctr_int <= card.counter:
        raise HTTPException(
            status_code=HTTPStatus.CONFLICT, detail="Link already used (replay)."
        )

    # Advance the counter now — prevents replay even if the PIN check below fails.
    await update_card_counter(ctr_int, card.id)
    ip = request.client.host if (request and request.client) else ""
    if request:
        ip = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for") or ip
    agent = (request.headers.get("user-agent") or "") if request else ""
    await create_hit(card.id, ip, agent, card.counter, ctr_int)

    if pin and card.pin:
        if not verify_pin(pin, card.id, card.pin):
            total = await increment_card_pin_attempts(card.id)
            if total >= 3:
                await enable_disable_card(enable=False, card_id=card.id)
                raise HTTPException(
                    status_code=HTTPStatus.FORBIDDEN,
                    detail="Card blocked: too many incorrect PIN attempts.",
                )
            remaining = max(0, 3 - total)
            raise HTTPException(
                status_code=HTTPStatus.FORBIDDEN,
                detail=f"Invalid PIN. {remaining} attempt(s) remaining.",
            )
        await reset_card_pin_attempts(card.id)

    return {"verified": True, "card_id": card.id, "external_id": card.external_id}


@tagid_api_router.get("/api/v1/refunds")
async def api_refunds(
    key_info: WalletTypeInfo = Depends(require_invoice_key),
    all_wallets: bool = Query(False),
) -> list[Refund]:
    wallet_ids = [key_info.wallet.id]

    if all_wallets:
        user = await get_user(key_info.wallet.user)
        wallet_ids = user.wallet_ids if user else []

    cards = await get_cards(wallet_ids)
    cards_ids = []
    for card in cards:
        cards_ids.append(card.id)
    hits = await get_hits(cards_ids)
    hits_ids = []
    for hit in hits:
        hits_ids.append(hit.id)

    return await get_refunds(hits_ids)
