from fractions import gcd
import charm.core.math.pairing as pairing
from charm.toolbox.pairinggroup import PairingGroup, ZR, H, hashPair
import hashlib
import math
from typing import SupportsFloat

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

def num_Zn_star(n, fun, *args):
    """
    Random number in the multiplicative group of integers modulo n

    :param fun: Function that returns a number
    :param *args: Arguments that should be given to *fun*
    :return: Number in the multiplicative group of integers modulo n
    """
    while True:
        num = fun(*args)
        if gcd(int(num), int(n)) == 1:
            return num


def num_Zn_star_not_one(n, fun, *args):
    """
    Random number in the multiplicative group of integers modulo n which is not equal to 1

    :param fun: Function that returns a number
    :param *args: Arguments that should be given to *fun*
    :return: Number in the multiplicative group of integers modulo n which is not equal to 1
    """
    while True:
        num = num_Zn_star(n, fun, *args)
        if int(num) != 1:
            return num


def log2(x: SupportsFloat):
    assert x >= 0.0

    if x == 0.0:
        return 0.0
    else:
        return math.log2(x)


def hash_Zn(i: int, group: PairingGroup) -> pairing.pc_element:
    sha = hashlib.sha3_512()
    i_length = (int(log2(i)) // 8) + 1
    sha.update(i.to_bytes(i_length, byteorder="big"))
    digest = sha.digest()
    digest_int = int.from_bytes(digest, byteorder="big")
    return group.init(ZR, digest_int)

def hash_p(elem: pairing.pc_element) -> bytes:
    sha3 = hashlib.sha3_256()
    hashed = hashPair(elem)
    sha3.update(hashed)
    return sha3.digest()

def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes([x ^ y for x,y in zip(a, b)])

def poly_from_roots(roots):
    mutated_roots = []
    for root in roots:
        mutated_roots.append([-root, 1])

    if len(mutated_roots) > 1:
        result = mutated_roots[0]
        for i in range(1, len(mutated_roots)):
            result = _my_poly_root_evaluation(result, mutated_roots[i])
        return result
    else:
        return mutated_roots


def _my_poly_root_evaluation(a, b):
    c = [0] * (len(a) + len(b))
    for i in range(len(a)):
        for j in range(len(b)):
            c[i + j] = c[i + j] + a[i] * b[j]
    return c


def read_file(path: str) -> str:
    f = open(path, 'r')
    lines = f.readlines()

    s = ""
    for line in lines:
        s += line
    return s


def encrypt_document(doc: str) -> (bytes, bytes):
    doc_raw = doc.encode('utf-8')

    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(doc_raw)

    return key, cipher.nonce + tag + ciphertext


def decrypt_document(key: bytes, ciphertext: bytes) -> str:
    nonce, tag, ciphertext = ciphertext[:16], ciphertext[16:32], ciphertext[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    doc_raw = cipher.decrypt_and_verify(ciphertext, tag)

    return doc_raw.decode('utf-8')


if __name__ == '__main__':
    print(poly_from_roots([6, 2, 3]))
    print(poly_from_roots([2, 3]))