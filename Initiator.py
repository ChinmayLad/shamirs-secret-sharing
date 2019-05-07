import ShamirSecret
from Crypto.Util import number
import os


def save_to_file(line, filename, path=""):
    os.makedirs(path, exist_ok=True)
    with open(path + filename, "w+") as file:
        file.write(line)
        file.close()
    print(filename + " Saved!!")


def createPrimaryKey(filename, bits=128, path=""):
    x, g, p, q = ShamirSecret.generate_safe_prime(bits)
    save_to_file(str(x) + ":" + str(g) + ":" + str(p) + ":" + str(q), filename, path)


def create_share(spath, fsuffix, x, g, p, q, shares, threshold):
    if shares < threshold:
        raise ValueError("Shares must be than threshold " + shares +":"+ threshold)

    coeffs = [x]
    for i in range(threshold - 1):
        coeffs.append(number.getRandomRange(2, q - 1))

    for i in range(1, shares + 1):
        share = ShamirSecret.get_func_val(i, coeffs, q)
        line = str(i) + ":" + str(share) + ":" + str(g) + ":" + str(p) + ":" + str(q)
        save_to_file(line, fsuffix + str(i) + ".key", spath)


def main():
    bits = int(input("Enter number of bits: ").strip())
    x, g, p, q = ShamirSecret.generate_safe_prime(bits)
        # 12534561029141434529460171246998594158, 106279183146160203496477723386455201898, 226229198010949441507919068039136763503, 113114599005474720753959534019568381751
    save_to_file(str(x) + ":" + str(g) + ":" + str(p) + ":" + str(q), "private.key", "keys/")
    y = ShamirSecret.calculate_modular_exponentiation(g, x, p)
    save_to_file(str(y) + ":" + str(g) + ":" + str(p) + ":" + str(q), "public.key", "keys/")

    shares = int(input("Enter number of shares: ").strip())
    threshold = int(input("Enter minimum threshold: ").strip())

    create_share("shares/", "share_key", x, g, p, q, shares, threshold)
    message = int(input("Enter message to encrypt(should be number): ").strip())
    print(message)

    enc_message = ShamirSecret.encrypt(message, g, y, p, q)
    enc_text = str(enc_message[0])+":"+str(enc_message[1])
    save_to_file(enc_text, "encrypted.txt", "data/")


if __name__ == '__main__':
    main()
