import scrypt_backend
import base64, os, time, struct, binascii, six
from cryptography.hazmat.primitives import ciphers, hashes, hmac
from cryptography.hazmat.backends import default_backend, MultiBackend
from cryptography.exceptions import InvalidSignature


_MAX_CLOCK_SKEW = 60

#"Small" (byte 0x00): n=2^10, r=4, p=1
#"Medium" (byte 0x01): n=2^10, r=6, p=1
#"Large" (byte 0x02): n=2^11, r=8, p=1
#"Extra large" (byte 0x03): n=2^12, r=8, p=2

class Sizes:
    small = (2**10, 4, 1)
    medium = (2**10, 6, 1)
    large = (2**11, 8, 1)
    xlarge = (2**12, 8, 2)

class InvalidToken(Exception):
    pass


class PWFernet:
    def __init__(self, pw):
        if isinstance(pw, bytes) and pw:
            self.password = pw
        else:
            raise ValueError

        self.backend = MultiBackend([scrypt_backend.NewScryptBackend(), default_backend()])
        self.scryptsizes = {
            b'\x00': Sizes.small,
            b'\x01': Sizes.medium,
            b'\x02': Sizes.large,
            b'\x03': Sizes.xlarge,
        }


    def encrypt(self, message):

        # ensure the message is plaintext
        if not isinstance(message, bytes):
            raise TypeError("data must be bytes.")

        # generate Version, 8 bits
        version_field = b'\x90'

        # generate Timestamp, 64 bits; ">Q": big-endian unsigned long long integer of 8 bytes
        timestamp_field = struct.pack(">Q", int(time.time()))

        # generate salt field
        salt_field = os.urandom(16)

        # generate scryptsize field (adjustable)
        scryptsize_field = b'\x00'

        # generate password-based keys
        scryptsize_config = self.scryptsizes[scryptsize_field]

        kdf = scrypt_backend.Scrypt(salt=salt_field, length=64,
                                    n=scryptsize_config[0], r=scryptsize_config[1], p=scryptsize_config[2],
                                    backend=self.backend)

        key = kdf.derive(self.password)

        encryption_key = key[:32]
        authentication_key = key[32:]

        # Construct the ciphertext by encrypting the message using AES 256 in CTR mode with the fixed all-zeros IV and derived encryption key. Padding is not required.
        iv = b'0'*16 # IV is 256-bit for AES256; Unlike Python3.5, bytes is the same as string in Python2.7;
        encryptor = ciphers.Cipher(ciphers.algorithms.AES(encryption_key), ciphers.modes.CTR(iv), self.backend).encryptor()
        ciphertext_field = encryptor.update(message) + encryptor.finalize()

        # assembe the parts of message for hashing
        basic_parts = version_field + timestamp_field + scryptsize_field + salt_field + ciphertext_field

        # compute the HMAC field as described above using the derived authentication key.
        h = hmac.HMAC(authentication_key, hashes.SHA256(), backend=default_backend())
        h.update(basic_parts)
        hmac_field = h.finalize()

        # assemble token
        encoded_token = base64.urlsafe_b64encode(basic_parts + hmac_field)

        return encoded_token

    def decrypt(self, encoded_token, ttl=None):

        # ensure the encoded_token is of bytes type
        if not isinstance(encoded_token, bytes):
            raise TypeError("token must be bytes.")

        # ensure the encoded is encoded in urlsafe_b64
        try:
            token = base64.urlsafe_b64decode(encoded_token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        # ensure the first byte of the ciphertext is 0x90.
        version_field = six.indexbytes(token, 0)
        if not token or version_field != 0x90:
            raise InvalidToken

        # extract timestamp field
        try:
            timestamp_field,  = struct.unpack(">Q", token[1:9])
        except struct.error:
            raise InvalidToken

        # If the user has specified a maximum age (or "time-to-live") for the ciphertext,
        # ensure the recorded timestamp is not too far in the past.
        current_time = int(time.time())
        if ttl:
            # check only if ttl is not None
            if timestamp_field + ttl < current_time:
                raise InvalidToken

            if current_time + _MAX_CLOCK_SKEW < timestamp_field:
                raise InvalidToken

        # Eextract the Scrypt size from the token.
        scryptsize_field = token[9]

        # extract the salt field from the token
        salt_field = token[10:26]

        # Initialize Scrypt with the passphrase, salt, and work parameters corresponding to the given size.
        scryptsize_config = self.scryptsizes[scryptsize_field]

        # Derive encryption and authentication keys by generating 64 bytes of output with Scrypt.
        kdf = scrypt_backend.Scrypt(salt=salt_field, length=64,
                                    n=scryptsize_config[0], r=scryptsize_config[1], p=scryptsize_config[2],
                                    backend=self.backend)

        key = kdf.derive(self.password)

        # the encryption key is the first 32 bytes of the Scrypt output
        encryption_key = key[:32]

        # the authentication key is the second 32 bytes.
        authentication_key = key[32:]

        # Recompute the HMAC from the other fields and the derived authentication key.
        basic_parts = token[:-32]
        h = hmac.HMAC(authentication_key, hashes.SHA256(), backend=self.backend)
        h.update(basic_parts)

        # Ensure the recomputed HMAC matches the HMAC field stored in the ciphertext,
        # using a constant-time comparison function.
        hmac_field = token[-32:]
        try:
            h.verify(hmac_field)
        except InvalidSignature:
            raise InvalidToken

        # Decrypt the ciphertext field using AES 256 in CTR mode with the fixed all-zeros IV and derived encryption-key.
        # Output the decrypted message.
        iv = b'0' * 16
        ciphertext_field = token[26:-32]
        decryptor = ciphers.Cipher(
            ciphers.algorithms.AES(encryption_key), ciphers.modes.CTR(iv), self.backend
        ).decryptor()
        message = decryptor.update(ciphertext_field)
        try:
            message += decryptor.finalize()
        except ValueError:
            raise InvalidToken

        return message