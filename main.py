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


class Server:
    """ 
    This is the server (honest but curious)
    """

    def __init__(self, _PKs):
        """
        Initialize the server class with arguments ...
        """
        self.PKs = _PKs
        self.documents = []
    
    def update_public_key(self, t):
        self.PKs['X'] = self.PKs['X'] ** t

    def add_file(self, IR, file):
        """
        Add a client-generated index and encrypted file to the server
        """
        self.documents.append((IR, file))

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
        return V == PKs['group'].init(GT, 1)

    def search_index(self, TLp: List[pairing.pc_element], CTi):
        """
        Scan all secure indexes against the trapdoor. It takes as input:
        o Trapdoor `TLp`
        o System public key `self.PKs`
        o Membership Certificate `CTi`

        This function outputs the encrypted data `E(R)` for the member when 
        the data includes the searched keywords or "No Data Matched" for 
        the member when the data does not contain the keywords
        """
        if self.member_check(CTi):
            result = []

            for IR, file in self.documents:
                if self._test(TLp, IR):
                    result.append(file)
            
            return result

        else:
            return "Access Denied"

    ###
    #  /DataQuery
    ###

def test_index_trapdoor_test():
    c = Consultant(τ=512)
    server = Server(c.PKs)
    c.add_server(server)
    client = Client(c.PKs, c.SKg, server)
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
        set([Client(c.PKs, c.SKg, server) for _ in range(3)])
    )


def test_member_join():
    c = Consultant(τ=512)
    server = Server(c.PKs)
    c.add_server(server)

    c.group_auth(
        set([Client(c.PKs, c.SKg, server) for _ in range(3)])
    )
    c.member_join(
        set([Client(c.PKs, c.SKg, server) for _ in range(2)])
    )


def test_member_leave():
    c = Consultant(τ=512)
    server = Server(c.PKs)
    c.add_server(server)

    c.group_auth(
        set([Client(c.PKs, c.SKg, server) for _ in range(3)])
    )
    c.member_join(
        set([Client(c.PKs, c.SKg, server) for _ in range(2)])
    )

    to_leave = list(c.G)[2:4]
    c.member_leave(
        set(to_leave)
    )


def test_data_encrypt():
    c = Consultant(τ=512)
    server = Server(c.PKs)
    c.add_server(server)
    client = Client(c.PKs, c.SKg, server)

    D = read_file("documents/client0/doc0.txt")
    IR, R, Ed = client.index_gen(D)
    Ir, Er = client.data_encrypt(R, IR, Ed)
    client.server.add_file(IR, Er)


def test_member_check():
    c = Consultant(τ=512)
    server = Server(c.PKs)
    c.add_server(server)
    clients = [Client(c.PKs, c.SKg, server) for _ in range(5)]

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


def test_search_index():
    c = Consultant(τ=512)
    server = Server(c.PKs)
    c.add_server(server)
    clients = [Client(c.PKs, c.SKg, server) for _ in range(5)]

    c.group_auth(
        set(clients[:3])
    )

    for _ in range(5):
        D = read_file("documents/client0/doc0.txt")
        IR, R, Ed = clients[0].index_gen(D)
        Ir, Er = clients[0].data_encrypt(R, IR, Ed)
        clients[0].server.add_file(IR, Er)
    
    trapdoor = clients[2].make_trapdoor(['gold', 'dry', 'stead', 'heat'])
    search_results = server.search_index(trapdoor, clients[2].CTi)

    assert len(search_results) == 5, "Did not get 5 documents returned!"

    trapdoor = clients[2].make_trapdoor(['gold', 'dry', 'stead', 'test'])
    search_results = server.search_index(trapdoor, clients[2].CTi)

    assert len(search_results) == 0, "Got results when we should not have!"


def test_datadcrypt():
    c = Consultant(τ=512)
    server = Server(c.PKs)
    c.add_server(server)
    clients = [Client(c.PKs, c.SKg, server) for _ in range(5)]

    c.group_auth(
        set(clients[:3])
    )

    Rs = []

    for _ in range(5):
        D = read_file("documents/client0/doc0.txt")
        IR, R, Ed = clients[0].index_gen(D)
        Rs.append(R)
        Ir, Er = clients[0].data_encrypt(R, IR, Ed)
        clients[0].server.add_file(IR, Er)
    
    trapdoor = clients[2].make_trapdoor(['gold', 'dry', 'stead', 'heat'])
    search_results = server.search_index(trapdoor, clients[2].CTi)

    for i, result in enumerate(search_results):
        Up, ν = clients[2].data_aux(result, clients[2].CTi)
        D = c.get_decryption_key(Up, clients[2].CTi)
        Rp, Ed = clients[2].member_decrypt(result, D, ν)
        assert Rp == Rs[i], f"Recovered R not the same as encrypted R in round {i}!"

        print(decrypt_document(Rp, Ed))


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
    run_test(test_search_index)
    run_test(test_datadcrypt)
