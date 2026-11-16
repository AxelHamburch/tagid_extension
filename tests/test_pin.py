"""TagID-specific behaviour on top of the boltcards v1.2.x base:
PIN on withdrawals, card blocking, verify-only endpoint (ZapBox Ring-Login),
PIN reset on wipe, no PIN hash in API responses."""

import asyncio
from secrets import token_hex
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from lnbits.core.services.users import create_user_account_no_ckeck

from .. import services
from ..crud import get_card, get_hit
from .test_api import invoice, read_card, scan, tap

pytestmark = pytest.mark.asyncio(loop_scope="session")

PIN = "4711"


@pytest_asyncio.fixture(loop_scope="session")
async def pin_card(client, owner):
    _, wallet = owner
    response = await client.post(
        "/tagid/api/v1/cards",
        headers={"X-API-KEY": wallet.adminkey},
        json={
            "card_name": "PIN card",
            "uid": token_hex(7),
            "k0": token_hex(16),
            "k1": token_hex(16),
            "k2": token_hex(16),
            "tx_limit": 100,
            "daily_limit": 1000,
            "pin_limit": 10,
            "pin": PIN,
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert "pin" not in body and body["has_pin"] is True
    card = await get_card(body["id"])
    assert card and card.pin and card.pin != PIN
    return card


async def claim_pin(client, hit, amount_msat, pin=None):
    params = {"k1": hit["k1"], "pr": invoice(amount_msat)}
    if pin is not None:
        params["pin"] = pin
    return (await client.get(hit["callback"], params=params)).json()


async def verify(client, wallet, card, counter, pin=None):
    params = tap(card, counter)
    if pin is not None:
        params["pin"] = pin
    return await client.get(
        f"/tagid/api/v1/scan/verify/{card.external_id}",
        params=params,
        headers={"X-API-KEY": wallet.inkey},
    )


async def test_scan_advertises_pin_limit(client, pin_card):
    hit = await scan(client, pin_card, 1)
    assert hit["pinLimit"] == 10_000


async def test_small_amount_needs_no_pin(client, pin_card, monkeypatch):
    monkeypatch.setattr(services, "pay_invoice", AsyncMock())
    hit = await scan(client, pin_card, 1)
    assert (await claim_pin(client, hit, 9_000))["status"] == "OK"


async def test_pin_required_and_correct_pin_pays(client, pin_card, monkeypatch):
    pay = AsyncMock()
    monkeypatch.setattr(services, "pay_invoice", pay)
    hit = await scan(client, pin_card, 1)
    response = await claim_pin(client, hit, 10_000)
    assert response["status"] == "ERROR" and "PIN required" in response["reason"]
    response = await claim_pin(client, hit, 10_000, PIN)
    assert response["status"] == "OK"
    assert pay.await_count == 1


async def test_wrong_pin_keeps_hit_open_and_blocks_after_three(
    client, pin_card, monkeypatch
):
    pay = AsyncMock()
    monkeypatch.setattr(services, "pay_invoice", pay)
    hit = await scan(client, pin_card, 1)
    first = await claim_pin(client, hit, 20_000, "0000")
    assert first["status"] == "ERROR" and "Invalid PIN" in first["reason"]
    saved = await get_hit(hit["k1"])
    assert saved and not saved.spent and saved.pin_attempts == 1
    # Same k1 again (ZapBox PIN loop), still wrong.
    second = await claim_pin(client, hit, 20_000, "1111")
    assert "Invalid PIN" in second["reason"]
    third = await claim_pin(client, hit, 20_000, "2222")
    assert "blocked" in third["reason"]
    card = await read_card(pin_card.id)
    assert not card.enable and card.pin_total_attempts == 3
    assert (await get_hit(hit["k1"])).spent
    assert (await claim_pin(client, hit, 20_000, PIN))["status"] == "ERROR"
    assert pay.await_count == 0


async def test_parallel_wrong_pins_count_exactly(client, pin_card, monkeypatch):
    monkeypatch.setattr(services, "pay_invoice", AsyncMock())
    hit = await scan(client, pin_card, 1)
    responses = await asyncio.gather(
        *(claim_pin(client, hit, 20_000, f"{i:04d}") for i in range(5))
    )
    assert all(r["status"] == "ERROR" for r in responses)
    card = await read_card(pin_card.id)
    # Blocking happens at 3; later requests see a disabled card.
    assert card.pin_total_attempts == 3 and not card.enable


async def test_small_payment_does_not_reset_pin_counter(client, pin_card, monkeypatch):
    monkeypatch.setattr(services, "pay_invoice", AsyncMock())
    hit = await scan(client, pin_card, 1)
    await claim_pin(client, hit, 20_000, "0000")
    small = await scan(client, pin_card, 2)
    assert (await claim_pin(client, small, 1_000))["status"] == "OK"
    assert (await read_card(pin_card.id)).pin_total_attempts == 1


async def test_reenable_resets_pin_counter(client, owner, pin_card, monkeypatch):
    monkeypatch.setattr(services, "pay_invoice", AsyncMock())
    hit = await scan(client, pin_card, 1)
    for wrong in ("0000", "1111", "2222"):
        await claim_pin(client, hit, 20_000, wrong)
    response = await client.get(
        f"/tagid/api/v1/cards/enable/{pin_card.id}/true",
        headers={"X-API-KEY": owner[1].adminkey},
    )
    assert response.status_code == 200
    card = await read_card(pin_card.id)
    assert card.enable and card.pin_total_attempts == 0


async def test_edit_without_pin_keeps_hash(client, owner, pin_card):
    response = await client.put(
        f"/tagid/api/v1/cards/{pin_card.id}",
        headers={"X-API-KEY": owner[1].adminkey},
        json={
            "card_name": "renamed",
            "uid": pin_card.uid,
            "k0": pin_card.k0,
            "k1": pin_card.k1,
            "k2": pin_card.k2,
            "tx_limit": 100,
            "daily_limit": 1000,
            "pin_limit": 10,
            "pin": "",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["has_pin"] is True
    assert (await read_card(pin_card.id)).pin == pin_card.pin


async def test_invalid_pin_format_rejected(client, owner):
    response = await client.post(
        "/tagid/api/v1/cards",
        headers={"X-API-KEY": owner[1].adminkey},
        json={
            "card_name": "bad",
            "uid": token_hex(7),
            "k0": token_hex(16),
            "k1": token_hex(16),
            "k2": token_hex(16),
            "pin": "12a4",
        },
    )
    assert response.status_code == 400 or response.status_code == 422


async def test_wipe_resets_pin_settings(client, pin_card):
    response = await client.get(
        "/tagid/api/v1/auth", params={"a": pin_card.otp, "wipe": "true"}
    )
    assert response.status_code == 200
    card = await read_card(pin_card.id)
    assert card.pin is None and card.pin_limit is None
    assert card.pin_total_attempts == 0


# --------------------------------------------------------------------------- #
# Verify-only endpoint (ZapBox Ring-Login)
# --------------------------------------------------------------------------- #


async def test_verify_from_other_account_is_allowed(client, pin_card):
    # Rings from other accounts on the same server are a supported case.
    other = await create_user_account_no_ckeck(default_exts=["tagid"])
    response = await verify(client, other.wallets[0], pin_card, 1)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verified"] is True and body["card_id"] == pin_card.id
    assert body["pin_verified"] is False


async def test_verify_with_correct_pin(client, owner, pin_card):
    response = await verify(client, owner[1], pin_card, 1, PIN)
    assert response.status_code == 200
    assert response.json()["pin_verified"] is True


async def test_verify_wrong_pin_counts_and_blocks(client, owner, pin_card):
    for counter, expected in ((1, "2 attempt"), (2, "1 attempt"), (3, "blocked")):
        response = await verify(client, owner[1], pin_card, counter, "9999")
        assert response.status_code == 403
        assert expected in response.json()["detail"]
    assert not (await read_card(pin_card.id)).enable


async def test_verify_pin_ignored_for_card_without_pin(client, owner, card):
    response = await verify(client, owner[1], card, 1, "1234")
    assert response.status_code == 200
    assert response.json()["pin_verified"] is False
    assert (await read_card(card.id)).pin_total_attempts == 0


async def test_verify_replay_and_hit_not_payable(client, owner, card, monkeypatch):
    pay = AsyncMock()
    monkeypatch.setattr(services, "pay_invoice", pay)
    assert (await verify(client, owner[1], card, 1)).status_code == 200
    replay = await verify(client, owner[1], card, 1)
    assert replay.status_code == 409
    hits = await client.get(
        "/tagid/api/v1/hits", headers={"X-API-KEY": owner[1].adminkey}
    )
    verify_hits = [h for h in hits.json() if h["card_id"] == card.id]
    assert len(verify_hits) == 1
    assert verify_hits[0]["spent"] is True and verify_hits[0]["max_msat"] == 0


async def test_verify_requires_invoice_key(client, card):
    response = await client.get(
        f"/tagid/api/v1/scan/verify/{card.external_id}", params=tap(card, 1)
    )
    assert response.status_code == 401
