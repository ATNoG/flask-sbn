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

    def __init__(self, wsgiapp, key, logger, domainsuffix=''):
        self.wsgiapp = wsgiapp
        self.key = key
        self.logger = logger
        self.pathmarker = b'@'
        self.queryparam = b'sbnq='
        self.domainsuffix=domainsuffix

    def decrypt(self, ciphertext):
        return seccure.decrypt(ciphertext, self.key, CURVE)
    def encrypt(self, data):
        return seccure.passphrase_to_pubkey(self.key, CURVE).encrypt(data)

    def encrypt_host(self, host):
        data = self.encrypt(host)
        extra = uuid.uuid4().bytes
        data = b32encode(extra + data).strip(b'=')
        data = b'.'.join(chunks(data, 63))
        return data + self.domainsuffix.encode('utf8')
    def decrypt_host(self, host):
        data = host.split(self.domainsuffix.encode('utf8'))[0]
        data = data.replace(b'.', b'')
        data = pad_data(data)
        data = b32decode(data.upper())
        if len(data) < 16:
            raise Exception('Expecting at least 16 random bytes in host payload')
        data = data[16:]
        return self.decrypt(data)

    def decrypt_pathlabel(self, label):
        return self.decrypt(b64decode(label))

    def encrypt_pathlabel(self, label):
        if not label:
            # An empty path remains empty
            return label
        return self.pathmarker+b64encode(self.encrypt(label))
    def encrypt_query(self, query):
        if not query:
            return b''
        return self.queryparam+b64encode(self.encrypt(query))

    def decrypt_query(self, query):
        return self.decrypt(b64decode(query))

    def encrypt_path(self, path):
        labels = path.split('/')
        return b'/'.join([self.encrypt_pathlabel(label.encode('utf8')) for label in labels])

    def process_req(self, environ):
        # Host: this implementation works with host suffixes
        host = environ['HTTP_HOST']
        if self.domainsuffix and host.endswith(self.domainsuffix):
            environ['SBN_HTTP_HOST'] = environ['HTTP_HOST']
            environ['SBN_ENABLED'] = ''
            try:
                environ['HTTP_HOST'] = self.decrypt_host(host.encode('ascii')).decode('ascii')
            except Exception as e:
                self.logger.exception(e)
                e = BadRequest()
                return e(environ, start_response)

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
            self.logger.debug('Decrypted path %s' % (path))
            environ['SBN_ENABLED'] = ''
        else:
            self.logger.debug('Received clear path %s' % (environ['PATH_INFO']))

        # Query String
        if environ['QUERY_STRING'].startswith(self.queryparam.decode('utf8')):
            query = environ['QUERY_STRING']
            environ['SBN_QUERY_STRING'] = query
            environ['QUERY_STRING'] = self.decrypt_query(query[len(self.queryparam):]).decode('utf8')

    def __call__(self, environ, start_response):
        try:
            err = self.process_req(environ)
            if err:
                return err
        except binascii.Error:
            e = BadRequest()
            return e(environ, start_response)
        return self.wsgiapp(environ, start_response)

    def nosbn_url_for(self, endpoint, **values):
        values['_external'] = True
        url = flask_url_for(endpoint, **values)
        return url

    def url_for(self, endpoint, **values):
        """SBN wrapper around flask.url_for """
        values['_external'] = True
        url = flask_url_for(endpoint, **values)


        # FIXME: from the python docs this would urlp[4] but it is not
        urlp = list(urlsplit(url))
        urlp[3] = self.encrypt_query(urlp[3].encode('utf8')).decode('utf8')
        # FIXME: path params
        urlp[2] = self.encrypt_path(urlp[2]).decode('utf8')
        # TODO: this will break netloc w/username or password?
        if 'SBN_HTTP_HOST' in request.environ:
            urlp[1] = request.environ['SBN_HTTP_HOST']
        else:
            urlp[1] = self.encrypt_host(urlp[1].encode('utf8')).decode('utf8').lower()

        new_url = urlunsplit(urlp)
        return new_url


