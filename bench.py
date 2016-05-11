import sbn
import seccure

@profile
def bench():
    dec = sbn.SBNDecoder(sbndomain='domain.test')
    enc = sbn.SBNEncoder(str(seccure.passphrase_to_pubkey(dec.key)),
            sbndomain='domain.test')

    url = b'http://large-discouts.com/cars/used/2.html?color=red'
    for i in range(100):
        out = enc.encrypt(url)

bench()

