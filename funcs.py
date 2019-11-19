from fractions import gcd
import charm.core.math.pairing as pairing
from charm.toolbox.pairinggroup import PairingGroup, ZR, H, hashPair
import hashlib
import math
from typing import SupportsFloat, List, Union

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Signature import DSS
from Crypto.PublicKey import ECC

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


def hash_Zn(keyword: str, group: PairingGroup) -> pairing.pc_element:
    sha = hashlib.sha3_512()
    sha.update(keyword.encode())
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
        s += line + " "
    return s


def extract_keywords(doc: str) -> List[str]:
    # Remove leestekens
    doc = doc.replace(".", "")
    doc = doc.replace(",", "")
    doc = doc.replace("?", "")
    doc = doc.replace("!", "")
    doc = doc.replace("\n", "")

    # Remove duplicates
    doc = set(doc.split(" "))

    result = []

    for word in doc:
        result.append(word)
    
    return result


def encrypt_document(doc: bytes) -> (bytes, bytes):

    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_EAX)

    ciphertext, tag = cipher.encrypt_and_digest(doc)

    return key, cipher.nonce + tag + ciphertext


def gen_signing_key() -> ECC.EccKey:
    return ECC.generate(curve='secp521r1')


def decrypt_document(key: bytes, ciphertext: bytes) -> str:
    nonce, tag, ciphertext = ciphertext[:16], ciphertext[16:32], ciphertext[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    doc = cipher.decrypt_and_verify(ciphertext, tag)
    return doc


def trapdoor_to_bytes(trapdoor: List[pairing.pc_element]) -> bytes:
    assert len(trapdoor) > 0

    serialized = pairing.serialize(trapdoor[0])
    for t in trapdoor[1:]:
        serialized = serialized + pairing.serialize(t)
    
    return serialized


def sign_message(key, message: Union[bytes, List[pairing.pc_element]]) -> bytes:
    if isinstance(message, list):
        message = trapdoor_to_bytes(message)

    h = SHA512.new(message)
    signer = DSS.new(key, 'fips-186-3')
    return signer.sign(h)


def verify_message(pubkey, message: Union[bytes, List[pairing.pc_element]], signature: bytes) -> bool:
    if isinstance(message, list):
        message = trapdoor_to_bytes(message)
        
    h = SHA512.new(message)
    verifier = DSS.new(pubkey, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False


if __name__ == '__main__':
    print(poly_from_roots([6, 2, 3]))
    print(poly_from_roots([2, 3]))
