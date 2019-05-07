import ShamirSecret
from Crypto.Util import number


def calculate_shares(cipherfile, *pathtofiles):
    c1, c2 = 0, 0
    g, p, q = 0, 0, 0

    with open(cipherfile, "r") as cipher:
        line = cipher.readline()
        a, b = line.split(":")
        c1, c2 = number.bignum(a), number.bignum(b)

    for path in pathtofiles:
        with open(path, "r") as f:
            line = f.readline()
            i_str, share_str, g_str, p_str, q_str = line.split(":")
            i, share, g, p, q = int(i_str), number.bignum(share_str), number.bignum(g_str), number.bignum(p_str), number.bignum(q_str)
            i, d_share = ShamirSecret.create_decrypt_share((i, share), c1, p)
            ShamirSecret.save_to_file(str(i) + ":" + str(d_share) + ":" + g_str + ":" + p_str + ":" + q_str, "dshare"+str(i)+".share", "temp/")


def main():
    calculate_shares("data/encrypted.txt",
                     "shares/share_key1.key", "shares/share_key2.key",
                     "shares/share_key3.key", "shares/share_key4.key",
                     "shares/share_key5.key", "shares/share_key6.key")


if __name__ == '__main__':
    main()
