from fractions import gcd
import charm.core.math.pairing as pairing
from charm.toolbox.pairinggroup import PairingGroup, ZR
import hashlib
import math

def num_Zn_star(n, fun, *args):
    """
    Random number in the multiplicative group of integers modulo n

    :param fun: Function that returns a number
    :param *args: Arguments that should be given to *fun*
    :return: Number in the multiplicative group of integers modulo n
    """
    while True:
        num = fun( *args)
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

def hash_Zn(i: int, group: PairingGroup) -> pairing.pc_element:
    sha = hashlib.sha3_512()
    i_length = (int(math.log2(i)) // 8) + 1
    sha.update(i.to_bytes(i_length, byteorder="big"))
    digest = sha.digest()
    digest_int = int.from_bytes(digest, byteorder="big")
    return group.init(ZR, digest_int)
