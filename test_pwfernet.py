from __future__ import absolute_import, division, print_function
from pwfernet import *

import base64, calendar, time, iso8601
from cryptography.fernet import Fernet
import pytest

# most dict will fail and not give any result
test_vectors = [
    dict(password=b'password', salt=b'salt', size='small', timestamp=1490650404, message=b'a great secret message',
         result='6d1bb878eee9ce4a7b77d7a44103574d4cbfe3c15ae3940f0ffe75cd5e1e0afa'),
    dict(password=None, salt = None, size= 'medium ', timestamp=1490650404, message=b'a great secret message', result = ''),
    dict(password=b'', salt=b'', size='large', timestamp=1490650404, message=b'a great secret message', result=''),
    dict(password='', salt='', size='xlarge', timestamp=1490650404, message=b'a great secret message', result=''),
    dict(password=u'', salt=u'', size=None, timestamp=1490650404, message=b'a great secret message',result='')

]


class TestFernet(object):

    @pytest.mark.parametrize('password', [b'', '', None])
    def test_initialize_with_bad_key(self, password):
        with pytest.raises(ValueError):
            PWFernet(password)

    def test_roundtrip(self):
        password = b'password'
        f = PWFernet(password)
        original_message = b'Secret message!'
        assert original_message == f.decrypt(f.encrypt(original_message))

    def test_decrypt_invalid_start_byte(self):
        f = PWFernet(b'\x00' * 32)
        with pytest.raises(InvalidToken):
            f.decrypt(base64.urlsafe_b64encode(b'\x91'))

    def test_decrypt_timestamp_too_short(self):
        f = PWFernet(b'\x00' * 32)
        with pytest.raises(InvalidToken):
            f.decrypt(base64.urlsafe_b64encode(b'\x90abc'))

    @pytest.mark.parametrize('token', [b'\x90abc'])
    def test_decrypt_non_base64_token(self, token):
        f = PWFernet(b'\x00' * 32)
        with pytest.raises(InvalidToken):
            f.decrypt(token)

    @pytest.mark.parametrize('token', [u''])
    def test_decrypt_unicode(self, token):
        f = PWFernet(base64.urlsafe_b64encode(b'\x00' * 32))
        with pytest.raises(TypeError):
            f.decrypt(token)

    @pytest.mark.parametrize('message', [u''])
    def test_encrypt_unicode(self, message):
        f = PWFernet(base64.urlsafe_b64encode(b'\x00' * 32))
        with pytest.raises(TypeError):
            f.encrypt(message)


    @pytest.mark.parametrize('timestamp', ['1985-10-26T01:20:01-07:00', '2020-11-27T00:00:00-07:00'])
    def test_timestamp_ignored_no_ttl(self, timestamp, monkeypatch):
        f = Fernet(base64.urlsafe_b64encode(b'\x00' * 32))
        pt = b'encrypt me'
        token = f.encrypt(pt)
        current_time = calendar.timegm(iso8601.parse_date(timestamp).utctimetuple())
        monkeypatch.setattr(time, 'time', lambda: current_time)
        assert f.decrypt(token, ttl=None) == pt
