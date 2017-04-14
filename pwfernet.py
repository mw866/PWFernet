import scrypt_backend
import base64, os, time, struct
from cryptography.hazmat.primitives import ciphers, hashes, hmac
from cryptography.hazmat.backends import default_backend, MultiBackend

#"Small" (byte 0x00): n=2^10, r=4, p=1
#"Medium" (byte 0x01): n=2^10, r=6, p=1
#"Large" (byte 0x02): n=2^11, r=8, p=1
#"Extra large" (byte 0x03): n=2^12, r=8, p=2

class Sizes:
    small = (2**10, 4, 1)
    medium = (2**10, 6, 1)
    large = (2**11, 8, 1)
    xlarge = (2**12, 8, 2)


class PWFernet:
    def __init__(self, pw):
        self.password = pw
        self.backend = MultiBackend([scrypt_backend.NewScryptBackend(), default_backend()])


    def encrypt(self, message):

        # generate Version, 8 bits
        version_field = b'0x90'

        # generate Timestamp, 64 bits; ">Q": big-endian unsigned long long integer of 8 bytes
        timestamp_field = struct.pack(">Q", int(time.time()))

        # generate salt field
        salt_field = os.urandom(16)

        # generate scryptsize field (adjustable)
        scryptsize_field = b'0x00'

        # generate password-based keys
        scryptsize_config = ({
            b'0x00': Sizes.small,
            b'0x01': Sizes.medium,
            b'0x02': Sizes.large,
            b'0x03': Sizes.xlarge,
        }[scryptsize_field])

        kdf = scrypt_backend.Scrypt(salt=salt_field, length=64,
                                    n=scryptsize_config[0], r=scryptsize_config[1], p=scryptsize_config[2],
                                    backend=self.backend)
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        encryption_key = key[:32]
        authentication_key = key[32:]

        # gnerate ciphertext field
        iv = b'0'*16 # IV is 256-bit for AES256; Unlike Python3.5, bytes is the same as string in Python2.7;
        encryptor = ciphers.Cipher(ciphers.algorithms.AES(encryption_key),  ciphers.modes.CTR(iv), self.backend).encryptor()
        ciphertext_field = encryptor.update(message) + encryptor.finalize()


        # generate HMAC field
        hmacer = hmac.HMAC(authentication_key, hashes.SHA256(), backend=default_backend())
        hmacer.update(ciphertext_field)
        hmac_field = hmacer.finalize()

        # assemble token
        token = version_field + timestamp_field + scryptsize_field + salt_field + ciphertext_field + hmac_field

        return token

    def decrypt(self, ciphertext):
        # TODO
        pass

if __name__=='__main__':
    # TODO

    password = b"password"
    f = PWFernet(password)
    ciphertext = f.encrypt(b"Secret message!")
    print(ciphertext)
    # f.decrypt(ciphertext)
