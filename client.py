from typing import List, Dict, Set, Tuple, Callable
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair, order, H
import charm.core.math.pairing as pairing
from funcs import *
from keywords import keywords
from numpy.polynomial.polynomial import polyfromroots
import numpy as np
import uuid
import os
import rpyc
from rpyc.utils.server import ThreadedServer
import pickle
import time
import threading
import config
from serialization import *
import random
from Crypto.PublicKey import ECC


# DEBUG
import code
from charm.toolbox.pairingcurves import params as param_info  # dictionary with possible pairing param_id


class Client(rpyc.Service):
    """
    This is the client
    """

    def __init__(self):
        self.consultant = rpyc.connect(config.CONSULTANT_IP, config.CONSULTANT_PORT, config=config.config)
        self.server = rpyc.connect(config.SERVER_IP, config.SERVER_PORT, config=config.config)
        self.PKs = deserialize_PKs(self.consultant.root.get_public_parameters())
        self.id = uuid.uuid4().int
        self.port = random.randint(1024, 65535)
        self.CTi = None
        self.start_server()
        self.join_consultant()
        self.signingkey = gen_signing_key()
    
    ###
    #  DataGen
    #  Builds searchable encrypted data that are uploaded to the server.
    ###

    def exposed_add_certificate(self, _CTi):
        self.CTi = deserialize_CTi(_CTi, self.PKs)

    def exposed_update_certificate(self, t: pairing.pc_element):
        assert self.CTi is not None, "Client has no certificate to update!"
        t = self.PKs['group'].deserialize(t)

        ## Step 1
        self.PKs['X'] = self.PKs['X'] ** t

        ## Step 3
        self.CTi['ci'] = self.CTi['ci'] ** t

    def _build_index(self, L):
        """
        This function takes as input:
        o Keyword list `L`
        o System parameter PM = {`self.PKs`, `self.SKg`}

        This function outputs secure index `IL`
        """
        assert len(L) == self.PKs['l'], "Keyword list should be l long"
        SKg = self.SKg
        α = SKg['α']

        roots = []
        for word in L:
            roots.append(int(α * hash_Zn(keywords[word], self.PKs['group'])))

        polynomial_coefficients = list(polyfromroots(roots))

        rs = num_Zn_star_not_one(self.PKs['q'], self.PKs['group'].random, ZR)

        g = self.PKs['g']

        IL = [g ** (rs * self.PKs['group'].init(ZR, i)) for i in polynomial_coefficients]
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

        Er = (U, V, Ed, sign_message(self.signingkey, Ed))
        # Upload E(R) and Ir to the server; print for now
        return IR, Er

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
        SKg = self.SKg
        ru = num_Zn_star_not_one(self.PKs['q'], self.PKs['group'].random, ZR)
        T = []
        if len(Lp) > self.PKs['l']:
            raise ValueError("Length of Lp needs to be smaller than l")
        for i in range(self.PKs['l'] + 1):
            i = self.PKs['group'].init(ZR, i)
            Ti = self.PKs['group'].init(G1, 1)
            for j in range(len(Lp)):
                word = keywords[Lp[j]]  # What if keyword not in keywordlist?
                Tij = self.PKs['g'] ** (ru * (SKg['α'] * hash_Zn(word, self.PKs['group'])) ** i)
                Ti = Ti * Tij
            T.append(Ti)
        return T

    def make_trapdoor(self, Lp: List[str]):
        """
        This function is executed by a group member to make a trapdoor of a list of keywords the
        member want to search. It takes as input:
        o A keyword list `Lp`
        o System public key `self.PKs`
        o Group secret key `SKg`

        This function generates the trapdoor `TLp` of `Lp`, and outputs a query `(TLp, self.CTi)` to the server
        """
        return self._trapdoor(Lp)   # should also send a search request to server?

    ###
    #  /DataQuery
    ###

    ###
    #  DataDcrypt
    #  Decrypts the encrypted data
    ###

    def data_aux(self, Er):
        """
        This function is executed by a member to make an auxiliary information request associated with
        the encrypted data to the GM. It takes as input:
        o The encrypted data `E(R)`
        o The membership certificate `self.CTi`
        o System public key `self.PKs`

        This function outputs an auxiliary infromation `(Up, self.CTi)` for the GM, and a one-time secret
        key `v` for the member.
        """
        group = self.PKs['group']
        q = self.PKs['q']

        U, _V, _Ed = Er

        μ = num_Zn_star_not_one(q, group.random, ZR)
        ν = ~μ

        Up = U ** μ

        ## Send (U', self.CTi) to Consultant to get decryption key

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

    #Unused!
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


    def upload_file(self, file_location, recipient: int=-1):
        assert self.CTi is not None, "Client needs a certificate!"
        
        if recipient == -1:
            recipient = self.id

        D = read_file(file_location)
        IR, R, Ed = self.index_gen(D)
        Ir, Er = self.data_encrypt(R, IR, Ed)
        IrSerialized = serialize_IL(Ir, self.PKs)

        self.server.root.add_file(IrSerialized, serialize_Er(Er, self.PKs), recipient)

    
    def get_files_by_keywords(self, keywords):
        assert self.CTi is not None, "Client needs a certificate!"

        files = []
        group = self.PKs['group']
        trapdoor = self.make_trapdoor(keywords)
        CTi_serialized = serialize_CTi(self.CTi, self.PKs)

        signature = sign_message(self.signingkey, trapdoor)

        search_results = self.server.root.search_index(serialize_trapdoor(trapdoor, self.PKs), CTi_serialized, signature)
        if search_results == config.ACCESS_DENIED:
            return config.ACCESS_DENIED
        for i, result in enumerate(search_results):
            result = deserialize_Er(result, self.PKs)
            Up, ν = self.data_aux(result)
            D = group.deserialize(self.consultant.root.get_decryption_key(group.serialize(Up), CTi_serialized))
            Rp, Ed = self.member_decrypt(result, D, ν)
            files.append(decrypt_document(Rp, Ed))
        return files

    
    def join_consultant(self):
        assert self.CTi is None, "Client already has a certificate!"
        self.SKg = deserialize_SKg(self.consultant.root.join(self.port, self.id, self.signingkey.public_key()), self.PKs)

    def start_server(self):
        t = ThreadedServer(self, port=self.port, protocol_config=config.config)
        thread = threading.Thread(target=t.start)
        thread.start()

if __name__ == "__main__":
    client = Client()
    print("uploading file")
    client.upload_file("test.txt")
    print(client.get_files_by_keywords(["from", "the"]))
