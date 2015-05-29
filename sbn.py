from flask import url_for as flask_url_for
from flask import request
from werkzeug.exceptions import BadRequest

import seccure
from base64 import urlsafe_b64encode as b64encode
from base64 import urlsafe_b64decode as b64decode
from base64 import b32decode, b32encode
from urllib.parse import urlsplit, urlunsplit
import uuid
import binascii

#TODO: Rewrite Referer
# TODO: caching

def chunks(l, chunksize):
    result = []
    for i in range(len(l)):
        pos = i // chunksize
        if pos >= len(result):
            result.append(l[i:i+1])
        else:
            result[pos] += l[i:i+1]
    return result

def pad_data(data, multiple=8):
    c = 0
    while (len(data) + c) % multiple != 0:
        c +=1
    return data + b'='*c


CURVE = 'secp256r1/nistp256'
class SBNMiddleware(object):

    def __init__(self, app, key, logger, domainsuffix=''):
        self.wsgiapp = app.wsgi_app
        app.wsgi_app = self
        self.key = key
        self.logger = logger
        self.pathmarker = b'@'
        self.queryparam = b'sbnq='
        self.domainsuffix=domainsuffix

        self.decrypt_cache = {}
        self.encrypt_cache = {}

        # Replace default  url_for function with SBN.url_for
        app.jinja_env.globals['nosbn_url_for'] = self.nosbn_url_for
        app.jinja_env.globals['url_for'] = self.url_for

        self._process_stat_keys = [
                'miss_encrypt_host', 'miss_decrypt_host',
                'hit_encrypt_host', 'hit_decrypt_host',
                'miss_encrypt_pathlabel', 'miss_decrypt_pathlabel',
                'hit_encrypt_pathlabel', 'hit_decrypt_pathlabel',
                'miss_encrypt_query', 'hit_encrypt_query',
                'miss_decrypt_query', 'hit_decrypt_query',
                ]
        self.reset_process_stats()

    def reset_process_stats(self):
        self._process_stats = {}
        for k in self._process_stat_keys:
            self._process_stats[k] = 0
    def stats(self):
        return self._process_stats

    def decrypt(self, ciphertext):
        plain = seccure.decrypt(ciphertext, self.key, CURVE)
        self.decrypt_cache[ciphertext] = plain
        self.encrypt_cache[plain] = ciphertext
        return plain
    def encrypt(self, plain):

        ciphertext = seccure.passphrase_to_pubkey(self.key, CURVE).encrypt(plain)
        self.encrypt_cache[plain] = ciphertext
        return ciphertext

    def encrypt_host(self, host):

        extra = uuid.uuid4().bytes
        plain = extra+host
        # Stats/cache
        if plain in self.encrypt_cache:
            self._process_stats['hit_encrypt_host'] += 1
            data = self.encrypt_cache[plain]
        else:
            data = self.encrypt(plain)
            self._process_stats['miss_encrypt_host'] += 1

        data = b32encode(data).strip(b'=')
        data = b'.'.join(chunks(data, 63))
        return data + self.domainsuffix.encode('utf8')
    def decrypt_host(self, host):
        data = host.split(self.domainsuffix.encode('utf8'))[0]
        data = data.replace(b'.', b'')
        data = pad_data(data)
        ciphertext = b32decode(data.upper())

        # Stats/cache
        if ciphertext in self.decrypt_cache:
            self._process_stats['hit_decrypt_host'] += 1
            plain = self.decrypt_cache[ciphertext]
        else:
            self._process_stats['miss_decrypt_host'] += 1
            plain = self.decrypt(ciphertext)
            if len(plain) < 16:
                raise Exception('Expecting at least 16 random bytes in host payload')
        return plain[16:]

    def decrypt_pathlabel(self, label):
        ciphertext = b64decode(label)
        if ciphertext in self.decrypt_cache:
            self._process_stats['hit_decrypt_pathlabel'] += 1
            return self.decrypt_cache[ciphertext]

        self._process_stats['miss_decrypt_pathlabel'] += 1
        return self.decrypt(ciphertext)
    def encrypt_pathlabel(self, label):
        if not label:
            # An empty path remains empty
            return label
        # Stats/Cache
        if label in self.encrypt_cache:
            self._process_stats['hit_encrypt_pathlabel'] += 1
            ciphertext = self.encrypt_cache[label]
        else:
            self._process_stats['miss_encrypt_pathlabel'] += 1
            ciphertext = self.encrypt(label)
        return self.pathmarker+b64encode(ciphertext)

    def encrypt_query(self, query):
        if not query:
            return b''

        if query in self.encrypt_cache:
            self._process_stats['hit_encrypt_query'] += 1
            ciphertext = self.encrypt_cache[query]
        else:
            self._process_stats['miss_encrypt_query'] += 1
            ciphertext = self.encrypt(query)

        return self.queryparam+b64encode(ciphertext)
    def decrypt_query(self, query):
        ciphertext = b64decode(query)
        if ciphertext in self.decrypt_cache:
            self._process_stats['hit_decrypt_query'] += 1
            return self.decrypt_cache[ciphertext]
        self._process_stats['miss_decrypt_query'] += 1
        return self.decrypt(ciphertext)

    def encrypt_path(self, path):
        labels = path.split('/')
        return b'/'.join([self.encrypt_pathlabel(label.encode('utf8')) for label in labels])

    def process_req(self, environ):
        # Host: this implementation works with host suffixes
        #host = environ['HTTP_HOST']
        host = environ['HTTP_X_HOST_FIX']
        if self.domainsuffix and host.endswith(self.domainsuffix):
            environ['SBN_HTTP_HOST'] = environ['HTTP_HOST']
            environ['SBN_ENABLED'] = ''
            try:
                environ['HTTP_HOST'] = self.decrypt_host(host.encode('ascii')).decode('ascii')
            except Exception as e:
                self.logger.exception(e)
                return BadRequest()

        # Path
        if '/'+self.pathmarker.decode('utf8') in environ['PATH_INFO']:
            environ['SBN_PATH_INFO'] = environ['PATH_INFO']
            path = environ['PATH_INFO'].split('/')
            new_path = []
            for label in path:
                if label.startswith('@'):
                    newlabel = self.decrypt_pathlabel(label[1:].encode('utf8'))
                    new_path.append(newlabel.decode('utf8'))
                else:
                    new_path.append(label)

            environ['PATH_INFO'] = '/'.join(new_path)
            environ['SBN_ENABLED'] = ''

        # Query String
        if environ['QUERY_STRING'].startswith(self.queryparam.decode('utf8')):
            environ['SBN_ENABLED'] = ''
            query = environ['QUERY_STRING']
            environ['SBN_QUERY_STRING'] = query
            environ['QUERY_STRING'] = self.decrypt_query(query[len(self.queryparam):]).decode('utf8')

    def __call__(self, environ, start_response):
        self.reset_process_stats()
        try:
            err = self.process_req(environ)
            if err:
                return err(environ, start_response)
        except binascii.Error:
            e = BadRequest()
            return e(environ, start_response)
        return self.wsgiapp(environ, start_response)

    def url_for(self, endpoint, **values):
        if 'SBN_ENABLED' in request.environ:
            return self.sbn_url_for(endpoint, **values)
        else:
            return self.nosbn_url_for(endpoint, **values)

    # These two are escape hatches for when you WANT to
    # override the default behaviour
    def nosbn_url_for(self, endpoint, **values):
        values['_external'] = True
        url = flask_url_for(endpoint, **values)
        return url
    def sbn_url_for(self, endpoint, **values):
        """SBN wrapper around flask.url_for """
        values['_external'] = True
        url = flask_url_for(endpoint, **values)
        return self.encode_url(url)

    def encode_url(self, url):
        # FIXME: from the python docs this would urlp[4] but it is not
        urlp = list(urlsplit(url))
        urlp[3] = self.encrypt_query(urlp[3].encode('utf8')).decode('utf8')
        # FIXME: path params
        urlp[2] = self.encrypt_path(urlp[2]).decode('utf8')
        # TODO: this will break netloc w/username or password?
#        if 'SBN_HTTP_HOST' in request.environ and urlp[1] == request.environ['SBN_HTTP_HOST']:
#            urlp[1] = request.environ['SBN_HTTP_HOST']
#        else:
        urlp[1] = self.encrypt_host(urlp[1].encode('utf8')).decode('utf8').lower()

        urlp[0] = 'http'
        url = urlunsplit(urlp)
        return url


