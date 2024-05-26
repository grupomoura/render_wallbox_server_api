import requests
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Depends, HTTPException, status
from fake_users_db import fake_users_db

from typing import List
from datetime import datetime, timedelta
from models import ChargerSchedule, EnergyCost, MaxChargingCurrent, MaxIcpCurrent, Token, TokenData, User, UserInDB
from wallbox import Wallbox
import os
from dotenv import load_dotenv
from security import (
    authenticate_user,
    create_access_token,
    get_current_user,
    get_current_admin,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import logging

# Carregar variáveis de ambiente do arquivo .env
load_dotenv()

# Configuração do logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(
    title="Wallbox API",
    description="API para interagir com carregadores Wallbox",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Configuração do CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permitir todas as origens
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"], 
)

ENVIRONMENT = os.getenv("ENVIRONMENT")
PORT = os.getenv("PORT") or 8000

# Regras de segurança no HEADER
if ENVIRONMENT == "production":
    from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
    # Redirecionar HTTP para HTTPS
    app.add_middleware(HTTPSRedirectMiddleware)

    # Middleware para adicionar headers de segurança
    @app.middleware("http")
    async def add_security_headers(request: requests.Request, call_next):
        response = await call_next(request)
        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "connect-src 'self';"
        )
        # Strict-Transport-Security
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        # X-Content-Type-Options
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # X-Frame-Options
        response.headers['X-Frame-Options'] = 'DENY'
        return response

# Recuperar credenciais do arquivo .env
WALLBOX_EMAIL = os.getenv("WALLBOX_EMAIL")
WALLBOX_PASSWORD = os.getenv("WALLBOX_PASSWORD")

# Inicializar a instância do cliente wallbox
wb = Wallbox(WALLBOX_EMAIL, WALLBOX_PASSWORD)

# Token de segurança simples
SECURITY_TOKEN = os.getenv("SECURITY_TOKEN")

def verify_token(token: str):
    if token != SECURITY_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")

# Authenticate with the credentials above
try:
    wb.authenticate()
    logger.info("Authenticated successfully")
except requests.exceptions.HTTPError as err:
    logger.error(f"Authentication failed: {err}")

# Print a list of chargers in the account
# logger.info("Available chargers: %s", wb.getChargersList())

# Test API
@app.get("/", summary="Chamada teste da API", description="Retorna uma mensagem padrão")
async def root():
    logger.info("Attempting test API")
    return {"message": "API para interagir com carregadores Wallbox"}

# Fluxo de autenticação OAuth2 usando token JWT
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/token", summary="Retorna token de autenticação", description="Retorna token de autenticação HS256 válido por 600mim", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    logger.info("Attempting to authenticate user")
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        logger.warning("Authentication failed for user: %s", form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires
    )
    logger.info("User %s authenticated successfully", user.username)
    return {"access_token": access_token, "token_type": "bearer"}
    
# Admin Acess Endpoints: 
@app.post("/chargers/{charger_id}/energy_cost", summary="Definir Custo de Energia", description="Define o custo de energia por kWh para o carregador especificado", dependencies=[Depends(get_current_admin)])
async def set_energy_cost(charger_id: int, cost: EnergyCost, current_user: UserInDB = Depends(get_current_admin)):
    wb.setEnergyCost(charger_id, cost.energyCost)
    logger.info(f"Setting energy cost for charger {charger_id}")
    return {"status": f"{charger_id} energy cost set"}

@app.post("/chargers/{charger_id}/restart", summary="Reiniciar Carregador", description="Reinicia (reboot) o carregador especificado", dependencies=[Depends(verify_token)])
async def restart_charger(charger_id: int, token: str):
    wb.restartCharger(charger_id)
    logger.info(f"Restarting charger {charger_id}")
    return {"status": f"{charger_id} restarting"}

@app.post("/chargers/{charger_id}/max_icp_current", summary="Definir Corrente Máxima de ICP", description="Define a corrente máxima de ICP disponível para o carregador especificado", dependencies=[Depends(verify_token)])
async def set_icp_max_current(charger_id: int, icp_current: MaxIcpCurrent, token: str):
    wb.setIcpMaxCurrent(charger_id, icp_current.newIcpMaxCurrentValue)
    logger.info(f"Setting ICP max current for charger {charger_id}")
    return {"status": f"{charger_id} ICP max current set"}

# User Interface Endpoints:
@app.get("/users/me", summary="Listar Dados do usuário atual", description="Retorna a lista de dados do usuário atual", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_user)):
    logger.info("Getting current user data for %s", current_user.username)
    return current_user

@app.get("/chargers", summary="Listar Carregadores", description="Retorna a lista de carregadores disponíveis na conta", dependencies=[Depends(get_current_user)])
async def get_chargers_list(current_user: UserInDB = Depends(get_current_user)):
    logger.info("Getting list of chargers for user %s", current_user.username)
    return wb.getChargersList()

@app.get("/chargers/{charger_id}/status", summary="Obter Status do Carregador", description="Retorna o status do carregador especificado", dependencies=[Depends(get_current_user)])
async def get_charger_status(charger_id: int, current_user: User = Depends(get_current_user)):
    logger.info("Getting status for charger %d", charger_id)
    return wb.getChargerStatus(charger_id)

@app.post("/chargers/{charger_id}/unlock", summary="Desbloquear Carregador", description="Desbloqueia o carregador especificado", dependencies=[Depends(get_current_user)])
async def unlock_charger(charger_id: int, current_user: User = Depends(get_current_user)):
    wb.unlockCharger(charger_id)
    logger.info("Unlocking charger %d", charger_id)
    return {"status": f"{charger_id} unlocked"}

@app.post("/chargers/{charger_id}/lock", summary="Bloquear Carregador", description="Bloqueia o carregador especificado", dependencies=[Depends(get_current_user)])
async def lock_charger(charger_id: int, current_user: User = Depends(get_current_user)):
    wb.lockCharger(charger_id)
    logger.info("Locking charger %d", charger_id)
    return {"status": f"{charger_id} locked"}

@app.post("/chargers/{charger_id}/max_charging_current", summary="Definir Corrente Máxima de Carregamento", description="Define a corrente máxima de carregamento para o carregador especificado", dependencies=[Depends(get_current_user)])
async def set_max_charging_current(charger_id: int, max_current: MaxChargingCurrent, current_user: User = Depends(get_current_user)):
    wb.setMaxChargingCurrent(charger_id, max_current.chargingCurrentValue)
    logger.info("Setting max charging current for charger %d", charger_id)
    return {"status": f"{charger_id} max charging current set"}

@app.post("/chargers/{charger_id}/pause", summary="Pausar Sessão de Carregamento", description="Pausa a sessão de carregamento no carregador especificado", dependencies=[Depends(get_current_user)])
async def pause_charging_session(charger_id: int, current_user: User = Depends(get_current_user)):
    wb.pauseChargingSession(charger_id)
    logger.info("Pausing charging session for charger %d", charger_id)
    return {"status": f"{charger_id} paused"}

@app.post("/chargers/{charger_id}/resume", summary="Retomar Sessão de Carregamento", description="Retoma a sessão de carregamento no carregador especificado", dependencies=[Depends(get_current_user)])
async def resume_charging_session(charger_id: int, current_user: User = Depends(get_current_user)):
    wb.resumeChargingSession(charger_id)
    logger.info("Resuming charging session for charger %d", charger_id)
    return {"status": f"Session {charger_id} resumed"}

@app.post("/chargers/{charger_id}/resume_schedule", summary="Retomar Agendamento", description="Retoma o agendamento padrão do carregador após iniciar manualmente uma sessão de carregamento", dependencies=[Depends(get_current_user)])
async def resume_schedule(charger_id: int, current_user: User = Depends(get_current_user)):
    wb.resumeSchedule(charger_id)
    logger.info("Resuming schedule for charger %d", charger_id)
    return {"status": f"schedule {charger_id} resumed"}

@app.get("/chargers/{charger_id}/sessions", summary="Listar Sessões de Carregamento", description="Fornece a lista de sessões de carregamento entre as datas especificadas", dependencies=[Depends(get_current_user)])
async def get_session_list(charger_id: int, start_date: datetime, end_date: datetime, current_user: User = Depends(get_current_user)):
    logger.info("Getting session list for charger %d from %s to %s", charger_id, start_date, end_date)
    return wb.getSessionList(charger_id, start_date, end_date)

@app.get("/chargers/{charger_id}/schedules", summary="Obter Agendamentos do Carregador", description="Obtém os agendamentos configurados atualmente para o carregador especificado", dependencies=[Depends(get_current_user)])
async def get_charger_schedules(charger_id: int, current_user: User = Depends(get_current_user)):
    logger.info("Getting schedules for charger %d", charger_id)
    return wb.getChargerSchedules(charger_id)

@app.post("/chargers/{charger_id}/schedules", summary="Definir Agendamentos do Carregador", description="Cria ou substitui um agendamento existente para o carregador especificado", dependencies=[Depends(get_current_user)])
async def set_charger_schedules(charger_id: int, schedules: List[ChargerSchedule], current_user: User = Depends(get_current_user)):
    wb.setChargerSchedules(charger_id, {"schedules": [schedule.dict() for schedule in schedules]})
    logger.info("Setting schedules for charger %d", charger_id)
    return {"status": f"schedules {charger_id} set"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
