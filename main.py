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

    def __init__(self, PKs, SKg):
        self.PKs = PKs
        self.SKg = SKg
    
    ###
    #  DataGen
    #  Builds searchable encrypted data that are uploaded to the server.
    ###

    def index_gen(self, R):
        """
        This function makes a secure index. It takes as input:
        o A data R
        o System public key `self.PKs`
        o Group secret key `self.SKg`

        This function outputs secure index IR
        """
        pass

    def data_encrypt(self, R, IR):
        """
        This function encrypts the data. It takes as input:
        o A data R
        o System public key `self.PKs`
        o Group secret key `self.SKg`
        o Secure index IR corresponding to data R

        This function outputs encrypted data E(R) and uploads E(R) to the server
        """
        pass

    ###
    #  /DataGen
    ###

    ###
    #  DataQuery
    #  Retrieves the encrypted data which contains specific keywords
    ###

    def _trapdoor(self, Lp):
        """
        This function takes as input:
        o Keyword list `Lp`
        o System parameter PM = {`self.PKs`, `self.SKg`}
        
        This function outputs the trapdoor `TLp` of the list `Lp`
        """
        PKs = self.PKs
        SKg = self.SKg
        ru = num_Zn_star_not_one(PKs['q'], PKs['group'].random, ZR)
        T = []
        if len(Lp) > PKs['l']:
            raise ValueError("Length of Lp needs to be smaller than l")
        for i in range(PKs['l'] + 1):
            i = PKs['group'].init(ZR, i)
            Ti = PKs['group'].init(G1, 1)
            for j in range(len(Lp)):
                word = keywords[Lp[j]]  # What if keyword not in keywordlist?
                Tij = PKs['g'] ** (ru * (SKg['α'] * hash_Zn(word, PKs['group'])) ** i)
                Ti = Ti * Tij
            T.append(Ti)
        return T
    
    def make_trapdoor(self, Lp):
        """
        This function is executed by a group member to make a trapdoor of a list of keywords the
        member want to search. It takes as input:
        o A keyword list `Lp`
        o System public key `PKs`
        o Group secret key `SKg`

        This function generates the trapdoor `TLp` of `Lp`, and outputs a query `(TLp, CTi)` to the server
        """
        pass
    
    ###
    #  /DataQuery
    ###

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
        SKg = self.SKg
        PKs = self.PKs
        α = SKg['α']

        roots = []
        for word in L:
            roots.append(int(α * hash_Zn(keywords[word], PKs['group'])))

        polynomial_coefficients = list(polyfromroots(roots))

        rs = num_Zn_star_not_one(PKs['q'], PKs['group'].random, ZR)

        g = PKs['g']

        IL = [g ** (rs * PKs['group'].init(ZR, i)) for i in polynomial_coefficients]
        return IL


class Consultant(Client):
    """ 
    This is also the group manager (GM)
    """

    def __init__(self, τ):
        self.τ = τ
        self.system_setup(τ)

    def system_setup(self, τ):
        """
        Instantiates the scheme. Has as inputs:
        o Security parameter `τ`

        This function is executed by the GM, and outputs the system public key `PKs`,
        the group secret key `SKg` for all group members and the master key MK for the GM.
        """
        group = PairingGroup('SS512', secparam=τ)
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

    ###
    #  AuthCodGen
    #  Generates the group membership certificates
    ###

    def group_auth(self, G):
        """
        This function is executed by the GM and makes the membership certificate for every member in `G`. Takes as input:
        o Identities {ID_i }; 1 <= i <= N of all members {M_i}; 1 <= i <= N in `G`
        o The system public key `self.PKs`
        o The master key `self.MK`

        This function outputs Membership certificates {CT_i}; 1 <= i <= N for all members
        """
        pass

    def member_join(self, G, Ms):
        """
        This function is executed by the GM, interacting with old members when there are new members who wish to join
        the group. It takes as input:
        o The certificates {CT_i}; 1 <= i <= N of all members in `G`
        o The identities {ID_N+i }; 1 <= i <= n of all newly joining members {M_N+i}; 1 <= i <= n in `G`
        o The system public key `self.PKs`
        o The master key `self.MK`

        This function outputs Membership certificates {CT_N+i}; 1 <= i <= N for all newly joining members, updated
        membership certificates for the old members {M_i}; 1 <= i <= N, and an updated parameter of the system public key PKs.
        """
        pass

    def member_leave(self, G, Ms):
        """
        This function is executed by the GM, interacting with the members after some members have left the group.
        It takes as input:
        o The certificates {CT_i}; 1 <= i <= N of all members in `G`
        o The identities {ID_ji }; 1 <= i <= n of all leaving members {M_ji}; 1 <= i <= n in `G`
        o The system public key `self.PKs`

        This function outputs updates membership certificates for the remaining members, and an updated parameter 
        of the system public key PKs.
        """
        pass

    ###
    #  /AuthCodGen
    ###

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
        self.PKs = _PKs

    def add_file(self, IR, file):
        """
        Add a client-generated index and encrypted file to the server
        """
        pass

    ###
    #  DataQuery
    #  Retrieves the encrypted data which contains specific keywords
    ###

    def member_check(self, CTi, PKs):
        """
        This function check the membership of a certificate. It takes as input:
        o Membership Certificate `CTi`
        o System public key `PKs`

        This function outputs either Yes for access granted, or Access Denied to
        terminate the protocol.
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

        PKs = self.PKs

        V = PKs['group'].pair_prod(TLp, IL)
        print(V)
        print(PKs['group'].init(GT, 1))
        return V == PKs['group'].init(GT, 1)

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

    ###
    #  /DataQuery
    ###


if __name__ == "__main__":
    c = Consultant(τ=512)
    client = Client(c.PKs, c.SKg)
    server = Server(c.PKs)
    word_list = ['gold', 'possible', 'plane', 'stead', 'dry', 'brought', 'heat', 'among', 'grand', 'ball']
    il = client.build_index(word_list)
    query = word_list[3:4]
    query = ['gold', 'dry', 'stead', 'heat']
    print(query)
    t = client._trapdoor(query)
    test = server._test(t, il)
    print(test)
