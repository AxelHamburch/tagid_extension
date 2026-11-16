import json
from datetime import datetime

from fastapi import Query
from lnurl.types import LnurlPayMetadata
from pydantic import BaseModel, Field, field_validator

ZERO_KEY = "00000000000000000000000000000000"


class CardInfo(BaseModel):
    """Card data without secrets (keys, OTP, PIN hash).

    Used for the public display page.
    """

    id: str
    wallet: str
    card_name: str
    uid: str
    external_id: str
    counter: int
    tx_limit: int
    daily_limit: int
    enable: bool
    time: datetime
    pin_limit: int | None = None
    pin_total_attempts: int = 0


class CardOut(CardInfo):
    """Card as returned by the admin-key API: keys and OTP (needed to program
    and wipe the card), but never the PIN hash. `has_pin` tells the UI whether
    a PIN is set."""

    k0: str
    k1: str
    k2: str
    prev_k0: str
    prev_k1: str
    prev_k2: str
    otp: str
    has_pin: bool = False


class Card(CardInfo):
    k0: str
    k1: str
    k2: str
    prev_k0: str
    prev_k1: str
    prev_k2: str
    otp: str
    pin: str | None = None

    def to_out(self) -> CardOut:
        return CardOut(**self.model_dump(exclude={"pin"}), has_pin=bool(self.pin))

    async def lnurlpay_metadata(self) -> LnurlPayMetadata:
        return LnurlPayMetadata(json.dumps([["text/plain", self.card_name]]))


class CreateCardData(BaseModel):
    card_name: str = Query(...)
    uid: str = Query(...)
    counter: int = Query(0, ge=0, le=16777215)
    tx_limit: int = Query(0, ge=0)
    daily_limit: int = Query(0, ge=0)
    enable: bool = Query(True)
    k0: str = Query(ZERO_KEY)
    k1: str = Query(ZERO_KEY)
    k2: str = Query(ZERO_KEY)
    prev_k0: str = Query(ZERO_KEY)
    prev_k1: str = Query(ZERO_KEY)
    prev_k2: str = Query(ZERO_KEY)
    pin_limit: int | None = Query(None, ge=0)
    # Plain 4-digit PIN from the form; stored only as hash. Empty = keep/none.
    pin: str | None = Query(None)

    @field_validator("pin", mode="before")
    @classmethod
    def _validate_pin(cls, value):
        if value is None or value == "":
            return None
        value = str(value)
        if not (len(value) == 4 and value.isdigit()):
            raise ValueError("PIN must be exactly 4 digits.")
        return value


class Hit(BaseModel):
    id: str
    card_id: str
    ip: str
    spent: bool
    useragent: str
    old_ctr: int
    new_ctr: int
    amount: int
    amount_msat: int = 0
    max_msat: int = 0
    claimed_at: datetime | None = None
    time: datetime
    pin_attempts: int = 0


class Refund(BaseModel):
    id: str
    hit_id: str
    refund_amount: int
    time: datetime


class UIDPost(BaseModel):
    UID: str | None = Field(None, description="The UID of the card.")
    LNURLW: str | None = Field(None, description="The LNURLW of the card.")
