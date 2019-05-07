import ShamirSecret
from Crypto.Util import number
import os


def decrypt_message(cipherfile, dsharepath):
    c1, c2 = 0, 0
    g, p, q = 0, 0, 0

    with open(cipherfile, "r") as cipher:
        line = cipher.readline()
        a, b = line.split(":")
        c1, c2 = number.bignum(a), number.bignum(b)

    shares = []
    for path in os.listdir(dsharepath):
        with open(dsharepath+path, "r") as f:
            line = f.readline()
            i_str, dshare_str, g_str, p_str, q_str = line.split(":")
            i, dshare, g, p, q = int(i_str), number.bignum(dshare_str), number.bignum(g_str), number.bignum(p_str), number.bignum(q_str)
            shares.append((i, dshare))

    shares.sort(key=lambda x: x[0])
    message_byte = ShamirSecret.decrypt_shares((c1, c2), shares, p, q)
    # message = number.long_to_bytes(message_byte).decode('utf-8')
    print(message_byte)


decrypt_message("data/encrypted.txt", "temp/")
