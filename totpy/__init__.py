import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse
import qrcode

class TOTPAuthenticator:
    def __init__(self, secret: str = None, interval: int = 30, digits: int = 6):
        """
        Initialize authenticator
        If no secret is given a new secret is generated
        """
        self.interval = interval
        self.digits   = digits
        if secret is None:
            self.secret = self.generate_secret()
        else:
            self.secret = secret.upper()
        self.secret_bytes = base64.b32decode(self.secret, casefold=True)
    
    @staticmethod
    def generate_secret(length: int = 16) -> str:
        random_bytes = secrets.token_bytes(length)
        return base64.b32encode(random_bytes).decode('utf-8')
    
    def get_time_counter(self) -> int:
        for_time = int(time.time())
        return int(for_time // self.interval)
    
    def hotp(self, counter: int) -> int:
        # https://en.wikipedia.org/wiki/HMAC-based_one-time_password
        # Pack counter value in 8-byte big-endian format.
        counter_bytes  = struct.pack(">Q", counter)
        # Generate HMAC-SHA1 from secret and counter.
        hmac_hash      = hmac.new(self.secret_bytes, counter_bytes, hashlib.sha1).digest()
        # Dynamic truncation to get a 4-byte string
        offset         = hmac_hash[-1] & 0x0F
        truncated_hash = hmac_hash[offset:offset + 4]
        # Convert bytes to a 31-bit integer
        code           = struct.unpack(">I", truncated_hash)[0] & 0x7fffffff
        # Return the OTP value
        return code % (10 ** self.digits)
    
    def generate_current_otp(self) -> str:
        counter = self.get_time_counter()
        otp     = self.hotp(counter)
        return str(otp).zfill(self.digits)
    
    def verify_otp(self, otp: str, valid_window: int = 1) -> bool:
        current_counter = self.get_time_counter()
        candidate       = str(self.hotp(current_counter)).zfill(self.digits)
        return candidate == otp

    def get_secret(self) -> str:
        return self.secret

    def provisioning_uri(self, user: str, issuer: str) -> str:
        """
        Generate provisioning URI for authenticator apps
        """
        # URL-encode account and issuer values
        label = urllib.parse.quote(f"{issuer}:{user}")
        params = {
            "secret": self.secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": self.digits,
            "period": self.interval
        }
        query = urllib.parse.urlencode(params)
        return f"otpauth://totp/{label}?{query}"

    def provisioning_uri_qr_code(self, user: str, issuer: str):
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
        qr.add_data(self.provisioning_uri(user, issuer))
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        return img
