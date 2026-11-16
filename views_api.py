from http import HTTPStatus

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from limits import parse as parse_limit
from lnbits.core.crud import get_user
from lnbits.core.models import WalletTypeInfo
from lnbits.decorators import require_admin_key, require_invoice_key
from loguru import logger
from sqlalchemy.exc import IntegrityError

from .crud import (
    PinError,
    check_card_pin,
    create_card,
    create_hit,
    delete_card,
    enable_disable_card,
    get_card,
    get_card_by_uid,
    get_cards,
    get_hits,
    get_refunds,
    hash_pin,
    update_card,
)
from .models import CardOut, CreateCardData, Hit, Refund
from .services import (
    CardAuthError,
    CardDisabledError,
    CardNotFoundError,
    authenticate_tap,
)

tagid_api_router = APIRouter()


@tagid_api_router.get("/api/v1/cards")
async def api_cards(
    response: Response,
    key_info: WalletTypeInfo = Depends(require_admin_key),
    all_wallets: bool = False,
) -> list[CardOut]:
    response.headers["Cache-Control"] = "no-store"
    wallet_ids = [key_info.wallet.id]

    if all_wallets:
        user = await get_user(key_info.wallet.user)
        wallet_ids = user.wallet_ids if user else []

    logger.info("TagID card list retrieved: {}", key_info.wallet.id)
    return [card.to_out() for card in await get_cards(wallet_ids)]


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
    response: Response,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> CardOut:
    response.headers["Cache-Control"] = "no-store"
    card = await get_card(card_id)
    if not card:
        raise HTTPException(
            detail="Card does not exist.", status_code=HTTPStatus.NOT_FOUND
        )
    if card.wallet != wallet.wallet.id:
        raise HTTPException(detail="Not your card.", status_code=HTTPStatus.FORBIDDEN)
    check_uid = await get_card_by_uid(data.uid, wallet.wallet.id)
    if check_uid and check_uid.id != card_id:
        raise HTTPException(
            detail="UID already registered. Delete registered card and try again.",
            status_code=HTTPStatus.BAD_REQUEST,
        )
    original_pin = card.pin
    original_pin_total_attempts = card.pin_total_attempts
    for key, value in data.model_dump().items():
        setattr(card, key, value)
    card.uid = card.uid.upper()
    if data.pin:
        card.pin = hash_pin(data.pin, card.id)
        card.pin_total_attempts = 0
    else:
        # The UI always blanks the PIN field before showing the edit dialog
        # ("Leave empty to keep existing PIN"), so an empty value here must
        # never overwrite the stored hash.
        card.pin = original_pin
        card.pin_total_attempts = original_pin_total_attempts
    try:
        await update_card(card)
    except IntegrityError as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="Could not save card details."
        ) from exc
    return card.to_out()


@tagid_api_router.post(
    "/api/v1/cards",
    status_code=HTTPStatus.CREATED,
    dependencies=[Depends(validate_card)],
)
async def api_card_create(
    data: CreateCardData,
    response: Response,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> CardOut:
    response.headers["Cache-Control"] = "no-store"
    check_uid = await get_card_by_uid(data.uid, wallet.wallet.id)
    if check_uid:
        raise HTTPException(
            detail="UID already registered. Delete registered card and try again.",
            status_code=HTTPStatus.BAD_REQUEST,
        )
    try:
        card = await create_card(wallet_id=wallet.wallet.id, data=data)
    except IntegrityError as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail="Could not save card details."
        ) from exc
    if not card:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Could not create card.",
        )
    return card.to_out()


@tagid_api_router.get(
    "/api/v1/cards/enable/{card_id}/{enable}",
    status_code=HTTPStatus.OK,
)
async def enable_card(
    card_id: str,
    enable: bool,
    response: Response,
    wallet: WalletTypeInfo = Depends(require_admin_key),
) -> CardOut:
    response.headers["Cache-Control"] = "no-store"
    card = await get_card(card_id)
    if not card:
        raise HTTPException(detail="No card found.", status_code=HTTPStatus.NOT_FOUND)
    if card.wallet != wallet.wallet.id:
        raise HTTPException(detail="Not your card.", status_code=HTTPStatus.FORBIDDEN)
    try:
        card = await enable_disable_card(enable=enable, card_id=card_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)
        ) from exc
    if not card:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Could not update card.",
        )
    return card.to_out()


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
    response: Response,
    key_info: WalletTypeInfo = Depends(require_admin_key),
    all_wallets: bool = Query(False),
) -> list[Hit]:
    response.headers["Cache-Control"] = "no-store"
    wallet_ids = [key_info.wallet.id]

    if all_wallets:
        user = await get_user(key_info.wallet.user)
        wallet_ids = user.wallet_ids if user else []

    cards = await get_cards(wallet_ids)
    cards_ids = []
    for card in cards:
        cards_ids.append(card.id)

    return await get_hits(cards_ids)


def verify_request(request: Request, response: Response, external_id: str):
    """Rate limit for the verify endpoint, keyed per card (not per IP: all
    ZapBoxes of an instance call from the same server address)."""
    response.headers["Cache-Control"] = "no-store"
    limiter = getattr(request.app.state, "limiter", None)
    if limiter and not limiter.limiter.hit(
        parse_limit("10/minute"), "tagid-verify", external_id.lower()
    ):
        logger.warning("TagID verify rate limit exceeded: {}", external_id)
        raise HTTPException(
            status_code=HTTPStatus.TOO_MANY_REQUESTS, detail="Try again later."
        )


@tagid_api_router.get(
    "/api/v1/scan/verify/{external_id}", dependencies=[Depends(verify_request)]
)
async def api_scan_verify(
    request: Request,
    external_id: str,
    p: str = Query(...),
    c: str = Query(...),
    pin: str | None = Query(None),
    wallet: WalletTypeInfo = Depends(require_invoice_key),
) -> dict:
    """Verify-only check of a tap (ZapBox Ring-Login). No payment.

    Any wallet's invoice key of this instance is accepted: access control is
    the enrolment of the card on the ZapBox, and cards from other accounts on
    the same server are a supported case.

    The tap counter is advanced (replay protection) and a non-payable hit is
    recorded. If `pin` is given it is checked with the same counters/blocking
    as payments. `pin_verified` tells the caller whether a PIN was checked
    successfully, so it can enforce "PIN required" on its side.
    """
    try:
        card, counter = await authenticate_tap(external_id, p, c)
    except CardNotFoundError as exc:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail=str(exc)) from exc
    except CardDisabledError as exc:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail=str(exc)) from exc
    except CardAuthError as exc:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail=str(exc)) from exc

    ip = request.client.host if request.client else ""
    try:
        await create_hit(
            card,
            ip,
            request.headers.get("user-agent", ""),
            counter,
            payable=False,
        )
    except ValueError as exc:
        if "already used" in str(exc):
            raise HTTPException(
                status_code=HTTPStatus.CONFLICT, detail="Link already used (replay)."
            ) from exc
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail=str(exc)) from exc

    pin_verified = False
    # A PIN sent for a card without PIN is ignored (pin_verified stays False),
    # it must not count as a failed attempt.
    if pin and card.pin:
        try:
            await check_card_pin(card.id, pin)
        except PinError as exc:
            raise HTTPException(
                status_code=HTTPStatus.FORBIDDEN, detail=str(exc)
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=HTTPStatus.FORBIDDEN, detail=str(exc)
            ) from exc
        pin_verified = True

    logger.info(
        "TagID verify ok: card={} by wallet={} pin_verified={}",
        card.id,
        wallet.wallet.id,
        pin_verified,
    )
    return {
        "verified": True,
        "card_id": card.id,
        "external_id": card.external_id,
        "pin_verified": pin_verified,
    }


@tagid_api_router.get("/api/v1/refunds")
async def api_refunds(
    response: Response,
    key_info: WalletTypeInfo = Depends(require_admin_key),
    all_wallets: bool = Query(False),
) -> list[Refund]:
    response.headers["Cache-Control"] = "no-store"
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
