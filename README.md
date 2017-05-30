# PWFernet: a password-based authenticated encryption scheme 

PWFernet takes a user-provided message (an arbitrary sequence of bytes) and a password and produces a ciphertext, which contains the message in a form that can not be read or altered without the key. A timestamp can be used as an optional argument to encryption. If a timestamp is not provided, the implementation will generate one using its system clock.

## Usage

* Install dependency: `pip install cryptography pytest`
* Unit test: `pytest pwfernet.py`

## Token Format

| Field              | Length (Bytes)                   | Index                           |
| ------------------ | -------------------------------- | ------------------------------- |
| Version            | 1                                | [0]                             |
| Timestamp          | 8                                | [1:9]                           |
| Scrypt size        | 1                                | [10]                            |
| Salt               | 16                               | [11:26]                         |
| AES-CTR ciphertext | n (byte-aligned plaintexts only) | [26:-32] Note: 26 instead of 27 |
| HMAC               | 32                               | [-32:]                          |


## Reference
* Convert Integer to Bytes: 
    * https://docs.python.org/2.7/library/struct.html#struct.pack
    * http://stackoverflow.com/questions/14043886/python-2-3-convert-integer-to-bytes-cleanly

* pyca's Fernet Implementation: https://github.com/pyca/cryptography/blob/master/src/cryptography/fernet.py
* pyca's Fernet Test: https://github.com/pyca/cryptography/blob/master/tests/test_fernet.py
* Python Unit testing by Katy Huff: http://katyhuff.github.io/python-testing/05-pytest.html
