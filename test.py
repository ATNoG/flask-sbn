import sbn
import unittest
from cryptography.fernet import Fernet
from time import time
import seccure
import os

URLS = [
    'https://username:password@domain.test/p0/p1/p2;pparams?query=val#fragment',
    'https://username@domain.test/p0/p1/p2;pparams?query=val#fragment',
    'http://:password@domain.test/#fragment',
    ]
class TestBaseSBN(unittest.TestCase):
    """The Base SBN should return the same URL it was given"""

    s = sbn.BaseSBN()

    def test_convert(self):
        for url in URLS:
            self.assertEqual(self.s.convert_url(url), url)

class SBN(unittest.TestCase):

    dec = sbn.SBNDecoder(sbndomain='domain.test')
    enc = sbn.SBNEncoder(str(seccure.passphrase_to_pubkey(dec.key)),
            sbndomain='domain.test')
    def test_encode(self):
        for url in URLS:
            sbn_url = self.enc.convert_url(url)
            self.assertEqual(self.dec.convert_url(sbn_url), url)


if __name__ == '__main__':
    unittest.main()
