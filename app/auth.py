from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from flask import current_app

class AuthManager:
    def __init__(self, secret_key):
        self.secret_key = secret_key
    
    def hash_password(self, password):
        return generate_password_hash(password)
    
    def verify_password(self, hashed_password, password):
        return check_password_hash(hashed_password, password)
    
    def generate_token(self, user_id):
        payload = {
            'exp': datetime.utcnow() + timedelta(days=1),
            'iat': datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def verify_token(self, token):
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None