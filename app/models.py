from pydantic import BaseModel, Field


class HandshakeReq(BaseModel):
    product: str = Field(min_length=1)
    key: str = Field(min_length=1)
    hwid: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    ts: int
    sig: str = Field(min_length=1)


class VerifyReq(BaseModel):
    challenge_id: str = Field(min_length=1)
    key: str = Field(min_length=1)
    hwid: str = Field(min_length=1)
    ts: int
    answer_sig: str = Field(min_length=1)


class HwidResetReq(BaseModel):
    product: str = Field(min_length=1)
    key: str = Field(min_length=1)
    hwid: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    ts: int
    sig: str = Field(min_length=1)
