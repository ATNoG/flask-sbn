"""
Session Bound Namespaces(SBNs) in Python

SBNs are namespaces of encrypted URLs that retain the structural
characteristics of the original URLs.

This module provides an example SBNEncoder and SBNDecoder, but you
can extend BaseSBN to create your own encoder/decode, or if you just
want to use a different encryption scheme override the
encrypt/decrypt methods in each class.

For encryption/decryption the seccure python module is used i.e. the
encrypted bits have use the p160 ECC with an HMAC
"""

import seccure
from urllib.parse import urlsplit
import base64
import os

def chunks(l, chunksize):
    """Break apart list into fixed sized chunks"""
    result = []
    for i in range(len(l)):
        pos = i // chunksize
        if pos >= len(result):
            result.append(l[i:i+1])
        else:
            result[pos] += l[i:i+1]
    return result

def pad_data(data, multiple=8):
    """Pad base32 data with trailling ==="""
    count = 0
    while (len(data) + count) % multiple != 0:
        count += 1
    return data + b'='*count

class SBNException(Exception):
    """Base Exception for SBN errors"""
    pass

class BaseSBN:
    """
    Base class for SBN encoder decoder. This class parses URLs
    but returns them as they are given - override the relevant methods
    to implement a real SBN.

    The convention in this class (and derived classes) is that the input
    for the conversion function are bytestrings - convert_url() being the
    exception since it takes a string as **url**.
    """

    def convert_url(self, url):
        """Encode URL into the SBN"""
        purl = urlsplit(url.encode('utf8'))
        result = b''

        if purl.scheme:
            result += self.conv_scheme(purl.scheme) + b'://'
        if purl.password:
            result += self.conv_username(purl.username)
            result += b':'
            result += self.conv_password(purl.password)
            result += b'@'
        elif purl.username:
            result += self.conv_username(purl.username) + b'@'

        result += self.conv_hostname(purl.hostname)
        result += self.conv_path(purl.path)

        if purl.query:
            result += b'?'
            result += self.conv_query(purl.query)
        if purl.fragment:
            result += b'#' + self.conv_fragment(purl.fragment)
        return result.decode('ascii')

    def conv_scheme(self, scheme):
        return scheme
    def conv_username(self, username):
        return username
    def conv_password(self, password):
        return password
    def conv_hostname(self, hostname):
        return hostname
    def conv_path(self, path):
        return path
    def conv_query(self, query):
        return query
    def conv_fragment(self, fragment):
        return fragment

class SBNDecoder(BaseSBN):
    """Decoder for SBN URLs"""

    def __init__(self, key=None, marker=b'@', sbndomain=b'sbndomain.tk'):
        self.key = key or os.urandom(256)
        self.marker = marker
        if isinstance(sbndomain, str):
            self.sbndomain = sbndomain.encode('ascii').lower()
        else:
            self.sbndomain = sbndomain.lower()


    def decrypt(self, cipher):
        """Decrypt ciphertext using seccure"""
        return seccure.decrypt(cipher, self.key)
    def decrypt_b64(self, cipher):
        """Decode stripped base64 and decrypt it

        This methods strips the base64 padding, and calls the
        decrypt() method"""
        return self.decrypt(base64.urlsafe_b64decode(pad_data(cipher, 4)))

    def conv_hostname(self, hostname):
        """Convert hostname from SBN"""
        if not hostname == self.sbndomain and not hostname.endswith(b'.'+self.sbndomain):
            raise SBNException('Unknown SBN domain')
        inp = hostname.split(self.sbndomain)[0].replace(b'.', b'').upper()
        cipher = base64.b32decode(pad_data(inp))
        plain = self.decrypt(cipher)
        return plain

    def conv_path(self, path):
        """Convert path from SBN"""
        parts = path.split(b'/')
        new_parts = []
        for part in parts:
            if part.startswith(self.marker):
                plain = self.decrypt_b64(part[1:])
                new_parts.append(plain)
            else:
                new_parts.append(part)
        return b'/'.join(new_parts)

    def conv_query(self, query):
        """Convert query from SBN"""
        # TODO allow mixed query attributes
        if not query.startswith(self.marker):
            return query

        cipher = query[len(self.marker):]
        plain = self.decrypt_b64(cipher)
        return plain

class SBNEncoder(BaseSBN):

    def __init__(self, pubkey, marker=b'@', sbndomain=b'sbndomain.tk'):
        self.key = pubkey
        self.marker = marker
        if isinstance(sbndomain, str):
            self.sbndomain = sbndomain.encode('ascii').lower()
        else:
            self.sbndomain = sbndomain.lower()

    def encrypt(self, plain):
        """Encrypt plaintext using seccure"""
        return seccure.encrypt(plain, self.key)
    def encrypt_b64(self, plain):
        """Encrypt plaintext, return stripped base64"""
        return base64.urlsafe_b64encode(self.encrypt(plain)).rstrip(b'=')

    def conv_hostname(self, hostname):
        """Convert hostname into the SBN"""
        cipher = self.encrypt(hostname)
        data = base64.b32encode(cipher)
        data = b'.'.join(chunks(data.strip(b'='), 63))
        res = data.lower() + b'.' + self.sbndomain
        if len(res) > 253:
            raise SBNException('Hostname is too long')
        return res

    def conv_path(self, path):
        """Convert path into the SBN"""
        parts = path.split(b'/')
        new_parts = []
        for part in parts:
            if part:
                segment = self.marker + self.encrypt_b64(part)
            else:
                segment = b''
            new_parts.append(segment)
        return b'/'.join(new_parts)

    def conv_query(self, query):
        """Convert query into the SBN"""
        return self.marker + self.encrypt_b64(query)

def main():
    """Mininmal testing tool, using a static key"""
    import sys
    if len(sys.argv) != 3:
        print('Usage: sbn (-d|-e) <url>')
        sys.exit(-1)

    if sys.argv[1] not in ('-e', '-d'):
        print('Usage: sbn (-d|-e) <url>')
        sys.exit(-1)

    key = b'6nZJyL-tdFJx-7PEdh_XOeUDaBdhoCzQTtf-MLEA3FI='
    if sys.argv[1] == '-e':
        pubkey = str(seccure.passphrase_to_pubkey(key))
        out = SBNEncoder(pubkey).convert_url(sys.argv[2])
    else:
        out = SBNDecoder(key=key).convert_url(sys.argv[2])
    print(out)

if __name__ == '__main__':
    main()
