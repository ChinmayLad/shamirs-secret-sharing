import time

from Crypto.Util import number
from Crypto.Util.number import bignum


def timeit(method):
    def timed(*args, **kw):
        ts = time.time()
        result = method(*args, **kw)
        te = time.time()
        if 'log_time' in kw:
            name = kw.get('log_name', method.__name__.upper())
            kw['log_time'][name] = int((te - ts) * 1000)
        else:
            print('%r  %2.2f ms' % (method.__name__, (te - ts) * 1000))
        return result

    return timed


def generate_safe_prime(bits=160):
    g = bignum(0)
    while 1:
        q = bignum(number.getPrime(bits - 1))
        p = 2 * q + 1
        if number.isPrime(p):
            break

        while 1:
            g = number.getRandomRange(3, p)
            safe = 1

            if pow(g, 2, p) == 1:
                safe = 0

            if safe and pow(g, q, p) == 1:
                safe = 0

            if safe and divmod(p - 1, g)[1] == 0:
                safe = 0

            ginv = number.inverse(g, p)
            if safe and divmod(p - 1, ginv)[1] == 0:
                safe = 0

            if safe:
                break

    x = number.getRandomRange(2, q - 1)

    return x, g, p, q


def get_func_val(x, coeffs, prime):
    value = bignum(0)
    for coeff in reversed(coeffs[1:]):
        value += coeff
        value *= x
        value %= prime
    value = (value + coeffs[0]) % prime
    return value


def create_shares(bits, shares, threshold):
    x, g, p, q = generate_safe_prime(bits)

    coeffs = [x]
    for i in range(threshold - 1):
        coeffs.append(number.getRandomRange(2, q - 1))

    s = [(i, get_func_val(i, coeffs, q)) for i in range(1, shares+1)]
    return x, g, p, q, s


def calculate_modular_exponentiation(base, exp, prime):
    """
    Fast Modular Exponentiation.
    Taken from Wikibooks Algorithm Implementation
    https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Modular_Exponentiation
    """
    mod_exp = bignum(1)
    i = 0
    while (exp >> i) > 0:
        if (exp >> i) & 1:
            mod_exp = (mod_exp * base) % prime
        base = (base ** 2) % prime
        i += 1
    return mod_exp


def calculate_decrypt_share(share, c1, prime):
    _, y = share
    decrypt_share = calculate_modular_exponentiation(c1, y, prime)
    return decrypt_share


def lagrangian_interpolator(i, shares, p):
    nums = bignum(1)
    dens = bignum(1)
    for j in shares:
        if i != j:
            nums *= (0-j)
            dens *= (i-j)
    """
    Converts (a/b) mod p to (a*b_inv) mod p
    b_inv is inverse modulo of b mod p
    """
    den_inv = number.inverse(dens, p)
    nums = nums % p

    return nums * den_inv


def encrypt(message, g, y, p, q):
    k = number.getRandomRange(3, q - 1)
    c1 = calculate_modular_exponentiation(g, k, p)
    gk = calculate_modular_exponentiation(y, k, p)
    c2 = (message * gk) % p

    return c1, c2


def decrypt(cipher, x, p):
    """
    Normal decryption using private key x.
    """
    c1, c2 = cipher
    c = calculate_modular_exponentiation(c1, x, p)
    cinv = number.inverse(c, p)
    message = (c2 * cinv) % p

    return message


def create_decrypt_share(share_key, g, p):
    """
    Create the decrypting share for each participating party.
    di = (c1^si) mod p
    """
    i, fi = share_key
    d = calculate_modular_exponentiation(g, fi, p)
    return i, d


def decrypt_shares(cipher, d_shares, p, q):
    if len(d_shares) < 2:
        raise ValueError(" minimum 2 shares required")

    c1, c2 = cipher

    x_s, d_s = zip(*d_shares)
    lagrangian = [lagrangian_interpolator(i, x_s, q) for i in x_s]

    d_accum = bignum(1)
    for d, l in zip(d_s, lagrangian):
        di = pow(d, l, p)
        d_accum = (d_accum * di) % p

    dinv = number.inverse(d_accum % p, p)

    message = (c2 * dinv) % p

    return message


@timeit
def normal_encrypt_decrypt():
    x, g, p, q, s = create_shares(128, 10, 6)  # initializing variables and private key.
    y = calculate_modular_exponentiation(g, x, p)  # public key
    print("x: {}, g: {}, p: {}, q: {}, y: {}".format(x, g, p, q, y))

    message = "message"
    print("Message: " + str(message))

    # encryption
    message_byte = number.bytes_to_long(bytes(message, 'utf-8'))
    cipher_bytes = encrypt(message_byte, g, y, p, q)

    # normal decryption
    cipher = decrypt(cipher_bytes, x, p)
    print("Decrypted Message (x): " + number.long_to_bytes(cipher).decode('utf-8'))


@timeit
def shamirs_encrypt_decrypt():
    x, g, p, q, s = create_shares(128, 10, 6)  # initializing variables and private key.
    y = calculate_modular_exponentiation(g, x, p)  # public key
    print("x: {}, g: {}, p: {}, q: {}, y: {}".format(x, g, p, q, y))

    message = "message"
    print("Message: " + str(message))

    # encryption
    message_byte = number.bytes_to_long(bytes(message, 'utf-8'))
    cipher_bytes = encrypt(message_byte, g, y, p, q)

    # shamir secret decryption
    d_shares = [create_decrypt_share(s_i, cipher_bytes[0], p) for s_i in s]
    message_share = decrypt_shares(cipher_bytes, d_shares[:6], p, q)
    print("Decrypted Message: " + number.long_to_bytes(message_share).decode('utf-8'))


def verify_lagrange():
    x, g, p, q, s = create_shares(128, 10, 6)  # initializing variables and private key.

    print("x: {}".format(x))

    x_s, fi = zip(*s)
    lagrangian = [lagrangian_interpolator(i, x_s, q) for i in x_s]

    accum = bignum(0)
    for l, f in zip(lagrangian, fi):
        accum = (accum + (f * l) % q) % q

    print("Recreated key: " + str(accum))
    print(str(x == accum))


def main():
    print("verify lagrangian")
    verify_lagrange()

    print("-" * 20)

    print("Normal Encryption and Decryption:")
    normal_encrypt_decrypt()

    print("-"*20)

    print("Shamir Secret Encryption and Decryption")
    shamirs_encrypt_decrypt()


if __name__ == '__main__':
    main()
