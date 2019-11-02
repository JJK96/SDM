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

    def __init__(self, PKs, SKg):
        self.PKs = PKs
        self.SKg = SKg
        self.id = uuid.uuid4().int
    
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

    def index_gen(self, R):
        """
        This function makes a secure index. It takes as input:
        o A data R
        o System public key `self.PKs`
        o Group secret key `self.SKg`

        This function outputs secure index IR
        """
        keywords = ['gold', 'possible', 'plane', 'stead', 'dry', 'brought', 'heat', 'among', 'grand', 'ball'] # extract_keywords(R)
        
        return self._build_index(keywords)

    def data_encrypt(self, R, IR):
        """
        This function encrypts the data. It takes as input:
        o A data R
        o System public key `self.PKs`
        o Group secret key `self.SKg`
        o Secure index IR corresponding to data R

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

        Er = (U, V)
        # Upload E(R) and Ir to the server; print for now
        print(f"Uploading E(R)={Er} and IR={IR}")

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

    def data_aux(self, C, CTi, PKs):
        """
        This function is executed by a member to make an auxiliary information request associated with
        the encrypted data to the GM. It takes as input:
        o The encrypted data `E(R)`
        o The membership certificate `CTi`
        o System public key `self.PKs`

        This function outputs an auxiliary infromation `(Up, CTi)` for the GM, and a one-time secret
        key `v` for the member.
        """
        pass

    def member_decrypt(self, C, D, v):
        """
        This function is executed by the member to obtain the data. It takes as input:
        o The encrypted data `E(R)`
        o The decryption key `D`
        o System public key `self.PKs`
        o Group secret key `self.SKg`
        o Member one-time secret key `v`

        This function outputs the desired data `R`
        """
        pass

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


class Consultant(Client):
    """ 
    This is also the group manager (GM)
    """

    def __init__(self, τ):
        self.τ = τ
        self.system_setup(τ)
    
    def add_server(self, server):
        self.server = server

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

    def group_auth(self, G: Set[Client]):
        """
        This function is executed by the GM and makes the membership certificate for every member in `G`. Takes as input:
        o Identities {ID_i }; 1 <= i <= N of all members {M_i}; 1 <= i <= N in `G`
        o The system public key `self.PKs`
        o The master key `self.MK`

        This function outputs Membership certificates {CT_i}; 1 <= i <= N for all members
        """
        group = self.PKs['group']
        x = self.MK['x']
        y = self.MK['y']

        ## Step 1
        for member in G:
            ai = group.random(G1)
            bi = ai ** y
            ci = ai ** (x + hash_Zn(member.id, group) * x * y)

            CTi = {'IDi': member.id, 'ai': ai, 'bi': bi, 'ci': ci}
            member.add_certificate(CTi)
        
        # Save the members that are authenticated for later use
        self.G = G
        
        ## Step 2: keep CTi secret!

    def member_join(self, Ms: Set[Client]):
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
        assert self.G is not None, "group_auth needs to be called before member_join!"

        group = self.PKs['group']
        q = self.PKs['q']
        X = self.PKs['X']

        x = self.MK['x']
        y = self.MK['y']

        ## Step 1
        t = num_Zn_star_not_one(q, group.random, ZR)
        self.PKs['X'] = X ** t
        for member in self.G:
            member.update_certificate(t)
        self.server.update_public_key(t)

        ## Step 2
        for new_member in Ms:
            ai = group.random(G1)
            bi = ai ** y
            ci = ai ** (t * (x + hash_Zn(new_member.id, group) * x * y))

            CTi = {'IDi': member.id, 'ai': ai, 'bi': bi, 'ci': ci}
            new_member.add_certificate(CTi)
        
        # Add the new members to the member group
        self.G.update(Ms)
        
        ## Step 3: let old members update ci, we do this already in member.update_certificate

        ## Step 4: new members keep CTi secret!


    def member_leave(self, Ms: Set[Client]):
        """
        This function is executed by the GM, interacting with the members after some members have left the group.
        It takes as input:
        o The certificates {CT_i}; 1 <= i <= N of all members in `G`
        o The identities {ID_ji }; 1 <= i <= n of all leaving members {M_ji}; 1 <= i <= n in `G`
        o The system public key `self.PKs`

        This function outputs updates membership certificates for the remaining members, and an updated parameter
        of the system public key PKs.
        """
        group = self.PKs['group']
        q = self.PKs['q']
        X = self.PKs['X']

        ## Step 1
        t = num_Zn_star_not_one(q, group.random, ZR)
        self.PKs['X'] = X ** t
        for member in self.G.difference(Ms):
            member.update_certificate(t)
        self.server.update_public_key(t)
        
        # Remove the old members from the group
        self.G = self.G.difference(Ms)

        ## Step 2: let remaining members update ci, we do this already in member.update_certificate

        ## Step 3: remaining members keep CTi secret!

    ###
    #  /AuthCodGen
    ###

    ###
    #  DataDcrypt
    #  Decrypts the encrypted data
    ###

    def get_decryption_key(self, Up, CTi):
        """
        This function is executed by the GM to make a decryption key for the member. It takes as input:
        o The auxiliary information `(Up, CTi)`
        o System public key `self.PKs`
        o Group system key `self.SKg`
        o Master key `self.MK`

        This functions outputs the decryption key `D` or Access Denied for the member.
        """
        pass

    ###
    #  /DataDcrypt
    ###

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
    
    def update_public_key(self, t):
        self.PKs['X'] = self.PKs['X'] ** t

    def add_file(self, IR, file):
        """
        Add a client-generated index and encrypted file to the server
        """
        pass

    ###
    #  DataQuery
    #  Retrieves the encrypted data which contains specific keywords
    ###

    def member_check(self, CTi):
        """
        This function check the membership of a certificate. It takes as input:
        o Membership Certificate `CTi`
        o System public key `self.PKs`

        This function outputs either Yes for access granted, or Access Denied to
        terminate the protocol.
        """
        X = self.PKs['X']
        Y = self.PKs['Y']
        g = self.PKs['g']
        group = self.PKs['group']

        member = pair(CTi['ai'], Y) == pair(g, CTi['bi']) and \
            pair(X, CTi['ai']) * pair(X, CTi['bi']) ** hash_Zn(CTi['IDi'], group) == pair(g, CTi['ci'])
        
        return member

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

def test_index_trapdoor_test():
    c = Consultant(τ=512)
    client = Client(c.PKs, c.SKg)
    server = Server(c.PKs)
    c.add_server(server)
    word_list = ['gold', 'possible', 'plane', 'stead', 'dry', 'brought', 'heat', 'among', 'grand', 'ball']
    il = client._build_index(word_list)
    query = word_list[3:4]
    query = ['gold', 'dry', 'stead', 'heat']
    print(query)
    t = client._trapdoor(query)
    test = server._test(t, il)
    print(test)


def test_group_auth():
    c = Consultant(τ=512)
    server = Server(c.PKs)
    c.add_server(server)

    c.group_auth(
        set([Client(c.PKs, c.SKg) for _ in range(3)])
    )


def test_member_join():
    c = Consultant(τ=512)
    server = Server(c.PKs)
    c.add_server(server)

    c.group_auth(
        set([Client(c.PKs, c.SKg) for _ in range(3)])
    )
    c.member_join(
        set([Client(c.PKs, c.SKg) for _ in range(2)])
    )


def test_member_leave():
    c = Consultant(τ=512)
    server = Server(c.PKs)
    c.add_server(server)

    c.group_auth(
        set([Client(c.PKs, c.SKg) for _ in range(3)])
    )
    c.member_join(
        set([Client(c.PKs, c.SKg) for _ in range(2)])
    )

    to_leave = list(c.G)[2:4]
    c.member_leave(
        set(to_leave)
    )


def test_data_encrypt():
    c = Consultant(τ=512)
    client = Client(c.PKs, c.SKg)

    R = os.urandom(32)      # R will later probably by a 256-bit key used for hybrid encryption of a document, but is random bytes for now for testing
    IR = client.index_gen(R)
    client.data_encrypt(R, IR)


def test_member_check():
    c = Consultant(τ=512)
    clients = [Client(c.PKs, c.SKg) for _ in range(5)]
    server = Server(c.PKs)
    c.add_server(server)

    c.group_auth(
        set(clients[:3])
    )
    
    assert server.member_check(clients[0].CTi), "Client 0 should be member!"

    c.member_join(
        set(clients[3:5])
    )

    assert not server.member_check(clients[2].CTi), "Client 2 should be member!"
    assert not server.member_check(clients[4].CTi), "Client 4 should be member!"

    to_leave = list(c.G)[2:4]
    c.member_leave(
        set(to_leave)
    )

    assert not server.member_check(clients[2].CTi), "Client 2 should not be member!"


def run_test(test: Callable[[], None]):
    from time import time

    print(f"Running test {test}")
    t0 = time()
    
    test()

    t1 = time()
    print(f"Ran test {test} in {t1-t0} seconds")

if __name__ == "__main__":
    run_test(test_group_auth)
    run_test(test_member_join)
    run_test(test_member_leave)
    run_test(test_data_encrypt)
    run_test(test_member_check)
