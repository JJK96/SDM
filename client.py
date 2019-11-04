from typing import List, Dict, Set, Tuple, Callable
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair, order, H
import charm.core.math.pairing as pairing
from funcs import *
from keywords import keywords
from numpy.polynomial.polynomial import polyfromroots
import numpy as np
import uuid
import os

# DEBUG
import code
from charm.toolbox.pairingcurves import params as param_info  # dictionary with possible pairing param_id


class Client:
    """
    This is the client
    """

    def __init__(self, PKs, SKg, server):
        self.PKs = PKs
        self.SKg = SKg
        self.id = uuid.uuid4().int
        self.server = server
    
    def add_certificate(self, CTi: Dict[str, pairing.pc_element]):
        assert not hasattr(self, "CTi"), "Client already has a certificate!"

        self.CTi = CTi

    def update_certificate(self, t: pairing.pc_element):
        assert hasattr(self, "CTi"), "Client has no certificate to update!"

        ## Step 1
        self.PKs['X'] = self.PKs['X'] ** t

        ## Step 3
        self.CTi['ci'] = self.CTi['ci'] ** t


    ###
    #  DataGen
    #  Builds searchable encrypted data that are uploaded to the server.
    ###

    def _build_index(self, L):
        """
        This function takes as input:
        o Keyword list `L`
        o System parameter PM = {`self.PKs`, `self.SKg`}

        This function outputs secure index `IL`
        """
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

    def index_gen(self, D):
        """
        This function makes a secure index. It takes as input:
        o A document D
        o System public key `self.PKs`
        o Group secret key `self.SKg`

        This function outputs secure index IR, document encryption key R and encrypted document Ed
        """
        keywords = extract_keywords(D)
        print(keywords)
        R, Ed = encrypt_document(D)
        
        return self._build_index(keywords), R, Ed

    def data_encrypt(self, R, IR, Ed):
        """
        This function encrypts the data. It takes as input:
        o A data encryption key `R`
        o A encrypted data `Ed` encrypted with `R`
        o System public key `self.PKs`
        o Group secret key `self.SKg`
        o Secure index IR corresponding to data `R`

        This function outputs encrypted data E(R) and uploads E(R) to the server
        """
        group = self.PKs['group']
        q = self.PKs['q']
        P = self.SKg['P']
        Q = self.SKg['Q']
        Pp = self.SKg['Pp']

        γ = num_Zn_star_not_one(q, group.random, ZR)  # let op dit is een gamma, niet een standaard y
        U = P ** γ

        V = xor(R, hash_p(pair(Q, Pp) ** γ))

        Er = (U, V, Ed)
        # Upload E(R) and Ir to the server; print for now
        self.server.add_file(IR, Er)

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

    def make_trapdoor(self, Lp: List[str]):
        """
        This function is executed by a group member to make a trapdoor of a list of keywords the
        member want to search. It takes as input:
        o A keyword list `Lp`
        o System public key `PKs`
        o Group secret key `SKg`

        This function generates the trapdoor `TLp` of `Lp`, and outputs a query `(TLp, CTi)` to the server
        """
        return self._trapdoor(Lp)   # should also send a search request to server?

    ###
    #  /DataQuery
    ###

    ###
    #  DataDcrypt
    #  Decrypts the encrypted data
    ###

    def data_aux(self, Er, CTi):
        """
        This function is executed by a member to make an auxiliary information request associated with
        the encrypted data to the GM. It takes as input:
        o The encrypted data `E(R)`
        o The membership certificate `CTi`
        o System public key `self.PKs`

        This function outputs an auxiliary infromation `(Up, CTi)` for the GM, and a one-time secret
        key `v` for the member.
        """
        group = self.PKs['group']
        q = self.PKs['q']
        
        U, V, Ed = Er

        μ = num_Zn_star_not_one(q, group.random, ZR)
        ν = ~μ

        Up = U ** μ

        ## Send (U', CTi) to Consultant to get decryption key

        # Return Up, ν for now since we need to save it for decryption
        return Up, ν
        

    def member_decrypt(self, Er, D, ν):
        """
        This function is executed by the member to obtain the data. It takes as input:
        o The encrypted data `E(R)`
        o The decryption key `D`
        o System public key `self.PKs`
        o Group secret key `self.SKg`
        o Member one-time secret key `ν`

        This function outputs the desired data `R`
        """
        U, V, Ed = Er
        Qp = self.SKg['Qp']

        R = xor(V, hash_p((D ** ν) * pair(Qp, U)))
        return R, Ed

    ###
    #  /DataDcrypt
    ###

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
        α = SKg['α']

        roots = []
        for word in L:
            roots.append(α * hash_Zn(keywords[word], self.PKs['group']))

        polynomial_coefficients = list(polyfromroots(roots))

        rs = num_Zn_star_not_one(self.PKs['q'], self.PKs['group'].random, ZR)

        g = self.PKs['g']

        IL = [g ** (rs * i) for i in polynomial_coefficients]
        return IL
