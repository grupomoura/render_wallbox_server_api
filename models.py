from pydantic import BaseModel # type: ignore
from typing import Optional, Dict

# Modelos de entrada
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    role: str

class UserInDB(User):
    hashed_password: str
    role: str

class ChargerSchedule(BaseModel):
    id: int
    chargerId: int
    enable: int
    max_current: int
    max_energy: int
    days: Dict[str, bool]
    start: str
    stop: str

class EnergyCost(BaseModel):
    energyCost: float

class MaxChargingCurrent(BaseModel):
    chargingCurrentValue: int

class MaxIcpCurrent(BaseModel):
    newIcpMaxCurrentValue: int
