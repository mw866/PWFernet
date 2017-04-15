from __future__ import absolute_import, division, print_function
from pwfernet import *

import base64, calendar, time, iso8601
from cryptography.fernet import Fernet
import pytest

test_vectors = [
    dict(password=b'password', salt=b'salt', size='small', timestamp=1490650404, message=b'a great secret message',
         result='6d1bb878eee9ce4a7b77d7a44103574d4cbfe3c15ae3940f0ffe75cd5e1e0afa'),
    dict(password=None, salt = b'salt',size= 'small', timestamp=1490650404, message=b'a great secret message', result = '6d1bb878eee9ce4a7b77d7a44103574d4cbfe3c15ae3940f0ffe75cd5e1e0afa')
    dict(password=b'', salt=b'salt', size='small', timestamp=1490650404, message=b'a great secret message', result='6d1bb878eee9ce4a7b77d7a44103574d4cbfe3c15ae3940f0ffe75cd5e1e0afa')
    dict(password='', salt=b'salt', size='small', timestamp=1490650404, message=b'a great secret message',
         result='6d1bb878eee9ce4a7b77d7a44103574d4cbfe3c15ae3940f0ffe75cd5e1e0afa'),
    dict(password=u'', salt=b'salt', size='small', timestamp=1490650404, message=b'a great secret message',
         result='6d1bb878eee9ce4a7b77d7a44103574d4cbfe3c15ae3940f0ffe75cd5e1e0afa'),
]

@pytest.mark.parametrize('password, salt, size, timestamp, message, result', test_vectors)
class test_pwfernet:
    def test_initialize_with_bad_key(self, password):
        with pytest.raises(ValueError):
            PWFernet(password)

    def test_roundtrip(self, password):
        f = PWFernet(password)
        message = b'Secret message!'
        assert message == f.decrypt(f.encrypt(message))

    def test_decrypt_invalid_start_byte(self):
        f = PWFernet(b'\x00' * 32)
        with pytest.raises(InvalidToken):
            f.decrypt(base64.urlsafe_b64encode(b'\x91'))

    def test_decrypt_timestamp_too_short(self):
        f = PWFernet(b'\x00' * 32)
        with pytest.raises(InvalidToken):
            f.decrypt(base64.urlsafe_b64encode(b'\x90abc'))

    def test_decrypt_non_base64_token(self):
        f = PWFernet(b'\x00' * 32)
        with pytest.raises(InvalidToken):
            f.decrypt(b'\x90abc')

    def test_decrypt_unicode(self):
        f = PWFernet(base64.urlsafe_b64encode(b'\x00' * 32))
        with pytest.raises(TypeError):
            f.encrypt(u'')
        with pytest.raises(TypeError):
            f.decrypt(u'')

    def test_timestamp_ignored_no_ttl(self, monkeypatch):
        f = Fernet(base64.urlsafe_b64encode(b'\x00' * 32))
        pt = b'encrypt me'
        token = f.encrypt(pt)
        ts = '1985-10-26T01:20:01-07:00'
        current_time = calendar.timegm(iso8601.parse_date(ts).utctimetuple())
        monkeypatch.setattr(time, 'time', lambda: current_time)
        assert f.decrypt(token, ttl=None) == pt


''' 
    def test_various_input_length(self):
        # TODO
        pass
        
        @json_parametrize(
        ('secret', 'now', 'iv', 'src', 'token'), 'generate.json',
    )
    def test_generate(self, secret, now, iv, src, token, backend):
        f = Fernet(secret.encode('ascii'), backend=backend)
        actual_token = f._encrypt_from_parts(
            src.encode('ascii'),
            calendar.timegm(iso8601.parse_date(now).utctimetuple()),
            b''.join(map(six.int2byte, iv))
        )
        assert actual_token == token.encode('ascii')

    @json_parametrize(
        ('secret', 'now', 'src', 'ttl_sec', 'token'), 'verify.json',
    )
    def test_verify(self, secret, now, src, ttl_sec, token, backend,
                    monkeypatch):
        f = Fernet(secret.encode('ascii'), backend=backend)
        current_time = calendar.timegm(iso8601.parse_date(now).utctimetuple())
        monkeypatch.setattr(time, 'time', lambda: current_time)
        payload = f.decrypt(token.encode('ascii'), ttl=ttl_sec)
        assert payload == src.encode('ascii')

    @json_parametrize(('secret', 'token', 'now', 'ttl_sec'), 'invalid.json')
    def test_invalid(self, secret, token, now, ttl_sec, backend, monkeypatch):
        f = Fernet(secret.encode('ascii'), backend=backend)
        current_time = calendar.timegm(iso8601.parse_date(now).utctimetuple())
        monkeypatch.setattr(time, 'time', lambda: current_time)
        with pytest.raises(InvalidToken):
            f.decrypt(token.encode('ascii'), ttl=ttl_sec)

import cryptography_vectors

def json_parametrize(keys, filename):
    vector_file = cryptography_vectors.open_vector_file(
        os.path.join('fernet', filename), 'r'
    )
    with vector_file:
        data = json.load(vector_file)
        return pytest.mark.parametrize(keys, [
            tuple([entry[k] for k in keys])
            for entry in data
        ])

def test_default_backend():
    f = Fernet(Fernet.generate_key())
    assert f._backend is default_backend()

@pytest.mark.requires_backend_interface(interface=CipherBackend)
@pytest.mark.requires_backend_interface(interface=HMACBackend)
@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.AES(b'\x00' * 32), modes.CBC(b'\x00' * 16)
    ),
    skip_message='Does not support AES CBC',
)

'''


