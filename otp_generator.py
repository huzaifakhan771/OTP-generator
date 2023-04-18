import hashlib
import datetime
import hmac
import base64
import time

#Use secrets module if available (Python version >= 3.6)
try:
   from secrets import SystemRandom
except ImportError:
   from random import SystemRandom

random = SystemRandom()

class OTPGenerator:
    def __init__(self, digits: int = 6) -> None:
        """
        :param digits: number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        """
        self.digest = hashlib.sha1
        self.digits = digits
        self.secret_length = 32

    def generate_otp(self) -> str:
        hmac_counter = int(time.mktime(datetime.datetime.now().timetuple()))
        hasher = hmac.new(self.byte_secret(), self.int_to_bytestring(hmac_counter), self.digest)
        hmac_hash = bytearray(hasher.digest())
        offset = hmac_hash[-1] & 0xF
        code = (
            (hmac_hash[offset] & 0x7F) << 24
            | (hmac_hash[offset + 1] & 0xFF) << 16
            | (hmac_hash[offset + 2] & 0xFF) << 8
            | (hmac_hash[offset + 3] & 0xFF)
        )
        str_code = str(10_000_000_000 + (code % 10**self.digits))
        return str_code[-self.digits :]

    def byte_secret(self) -> bytes:
        chars = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')   # for creating a base32 secret
        secret = ''.join(random.choice(chars)for _ in range(self.secret_length))
        missing_padding = len(secret) % 8
        if missing_padding != 0:
            secret += "=" * (8 - missing_padding)
        return base64.b32decode(secret, casefold=True)

    @staticmethod
    def int_to_bytestring(i: int, padding: int = 8) -> bytes:
        """
        Turns an integer to the OATH specified
        bytestring, which is fed to the HMAC
        along with the secret
        """
        result = bytearray()
        while i != 0:
            result.append(i & 0xFF)
            i >>= 8
        return bytes(bytearray(reversed(result)).rjust(padding, b"\0"))

