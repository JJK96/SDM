from typing import List, Dict, Set, Tuple
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair, order, H
import charm.core.math.pairing as pairing
from funcs import *
from keywords import keywords
from numpy.polynomial.polynomial import polyfromroots
import numpy as np

# DEBUG
import code
from charm.toolbox.pairingcurves import params as param_info  # dictionary with possible pairing param_id


class Client:
    """
    This is the client
    """

    def __init__(self, consultant):
        self.consultant = consultant

    def make_trapdoor(self, Lp):
        PKs = self.consultant.PKs
        SKg = self.consultant.SKg
        ru = num_Zn_star_not_one(PKs['q'], PKs['group'].random, ZR)
        T = []
        if len(Lp) > PKs['l']:
            raise ValueError("Length of Lp needs to be smaller than l")
        for i in range(PKs['l'] + 1):
            Ti = 1
            for j in range(len(Lp)):
                word = keywords[Lp[j]]
                Tij = PKs['g'] ** (ru * (SKg['α'] * hash_Zn(word, PKs['group'])) ** i)
                Ti = Ti * Tij
            T.append(Ti)
        return T

    def search_indices(self, TLp, IR, PKs):
        pass

    def index_gen(self, R, PKs, SKg):
        pass

    def data_encrypt(self, R, PKs, SKg, IR):
        pass

    def data_aux(self, C, CTi, PKs):
        pass

    def send_file(self, file):
        pass

    def get_file(self, CTi, PKs, TLp):
        pass

    def get_decryption_key(self, Up, CTi):
        pass

    def mem_decrypt(self, C, D, PKs, SKg, v):
        pass

    def build_index(self, L):
        SKg = self.consultant.SKg
        α = SKg['α']

        roots = []
        for word in L:
            roots.append(int(α * hash_Zn(keywords[word], self.consultant.PKs['group'])))

        polynomial_coefficients = list(polyfromroots(roots))

        rs = num_Zn_star_not_one(self.consultant.PKs['q'], self.consultant.PKs['group'].random, ZR)

        g = self.consultant.PKs['g']

        IL = [g ** (rs * i) for i in polynomial_coefficients]
        return IL


class Consultant(Client):
    """ 
    This is also the group manager (GM)
    """

    def __init__(self):
        self.tau = 512
        self.system_setup()

    def system_setup(self):
        group = PairingGroup('SS512', secparam=self.tau)
        g, P, Q = [group.random(G1) for _ in range(3)]
        q = group.order()
        α, x, y, λ, σ = [num_Zn_star_not_one(q, group.random, ZR) for _ in range(5)]
        X = g ** x
        Y = g ** y
        Pp = P ** λ
        Qp = Q ** (λ - σ)
        self.PKs = {'l': 10, 'group': group, 'q': q, 'g': g, 'X': X, 'Y': Y}
        self.SKg = {'α': α, 'P': P, 'Pp': Pp, 'Q': Q, 'Qp': Qp}
        self.MK = {'x': x, 'y': y, 'λ': λ, 'σ': σ}
        # a = pair(g1**2, g2**3)
        # b = pair(g1, g2) ** 6
        # group.init(ZR, 10)
        # code.interact(local=dict(globals(), **locals()))

    def group_auth(self, g, PKs, MKg):
        pass

    def member_join(self, g, Ms, PKs, MKg):
        pass

    def member_leave(self, g, Ms, PKs):
        pass

    def get_decryption_key(self, Up, CTi, PKs, SKg, MK):
        pass

    def member_decrypt(self, C, D, PKs, SKg, v):
        pass

    def get_public_params(self):
        return self.PKs


class Server:
    """ 
    This is the server (honest but curious)
    """

    def __init__(self, _PKs):
        """
        Initialize the server class with arguments ...
        """
        self.group = _PKs['group']
        self.PKs = _PKs

    def add_file(self, IR, file):
        """
        Add a client-generated index and encrypted file to the server
        """
        pass

    def member_check(self, CTi, PKs):
        """
        Check the membership of a certificate. It takes as input:
        o Membership Certificate 
        """
        pass

    def _test(self, TLp: List[pairing.pc_element], IL: List[pairing.pc_element]) -> bool:
        """
        Test whether the index matches the trapdoor. It takes as input:
        o Trapdoor `TLp`
        o Secure index `IL`
        o System public key PKs
        """
        assert len(TLp) == len(IL), "Length of trapdoor and index do not match!"
        V = self.group.pair_prod(TLp, IL)
        print(V)
        print(self.group.init(GT, 1))
        return V == self.group.init(GT, 1)

    def search_index(self, TLp: List[pairing.pc_element], IR: List[List[pairing.pc_element]], PKs):
        """
        Scan all secure indexes against the trapdoor. It takes as input:
        o Trapdoor `TLp`
        o Secure index `IR`
        o System public key `PKs`

        This function outputs the encrypted data `E(R)` for the member when 
        the data includes the searched keywords or "No Data Matched" for 
        the member when the data does not contain the keywords
        """
        pass


if __name__ == "__main__":
    c = Consultant()
    client = Client(c)
    server = Server(c.PKs)
    word_list = ['gold', 'possible', 'plane', 'stead', 'dry', 'brought', 'heat', 'among', 'grand', 'ball']
    il = client.build_index(word_list)
    t = client.make_trapdoor(word_list)
    test = server._test(t, il)
    print(test)
