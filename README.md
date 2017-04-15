# PWFernet


## Design

Field|Length (Bytes)|Index
---|---|---
Version|1|[0]
Timestamp|8|[1:9]
Scrypt size|1|[10]
Salt|16|[11:26]
AES-CTR ciphertext| n (byte-aligned plaintexts only) |[26:-32] Note: 26 instead of 27
HMAC|32|[-32:]


## Reference
* Convert Integer to Bytes: 
    * https://docs.python.org/2.7/library/struct.html#struct.pack
    * http://stackoverflow.com/questions/14043886/python-2-3-convert-integer-to-bytes-cleanly

* pyca's Fernet Implementation: https://github.com/pyca/cryptography/blob/master/src/cryptography/fernet.py
* pyca's Fernet Test: https://github.com/pyca/cryptography/blob/master/tests/test_fernet.py
* Python Unit testing by Katy Huff: http://katyhuff.github.io/python-testing/05-pytest.html