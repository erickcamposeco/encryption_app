from cryptography.fernet import Fernet
from config import Config
from datetime import datetime, timedelta
import base64

class EncryptionService:
    def __init__(self, encryption_key=None):
        # Usa la clave de configuración si no se proporciona una
        self.key = encryption_key if encryption_key else Config.ENCRYPTION_KEY
        
        # Asegura que la clave esté en bytes
        if isinstance(self.key, str):
            self.key = self.key.encode()
        
        # Valida la clave
        try:
            self.cipher_suite = Fernet(self.key)
        except ValueError:
            raise ValueError("Clave Fernet inválida. Genera una nueva con EncryptionService.generate_key()")

    def encrypt_text(self, text):
        """Encripta texto y retorna el resultado codificado en base64"""
        return self.cipher_suite.encrypt(text.encode()).decode()

    def decrypt_text(self, encrypted_text):
        """Desencripta texto previamente encriptado"""
        return self.cipher_suite.decrypt(encrypted_text.encode()).decode()

    def generate_access_token(self, user_id, original_text):
        """Genera token con metadata del usuario"""
        data = f"{user_id}||{original_text}||{datetime.utcnow().isoformat()}"
        return self.encrypt_text(data)  # Reutiliza encrypt_text para consistencia

    def decode_access_token(self, token):
        """Extrae metadata del token"""
        try:
            data = self.decrypt_text(token)
            user_id, original_text, timestamp = data.split('||')
            return {
                'user_id': int(user_id),
                'original_text': original_text,
                'timestamp': timestamp
            }
        except Exception:
            return None