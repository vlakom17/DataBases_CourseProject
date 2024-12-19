from jose import jwt
from datetime import datetime, timedelta
from typing import Dict

def generate_token(data: Dict[str, str], secret_key: str, expiration=24):
    payload = data.copy()  # Скопируем переданные данные в payload
    payload['exp'] = datetime.utcnow() + timedelta(hours=expiration)
    return jwt.encode(payload, secret_key, algorithm='HS256')