from passlib.context import CryptContext # type: ignore

# Contexto de criptografia de senha
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# "Banco de dados" fake
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "hashed_password": pwd_context.hash("secret"),
        "role": "user"
    },
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("adminsecret"),
        "role": "admin"
    }
}
