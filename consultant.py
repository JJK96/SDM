from typing import List, Dict, Set, Tuple, Callable
import rpyc
from rpyc.utils.server import ThreadedServer # or ForkingServer
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair
from funcs import *
from client import Client
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler

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
        self.PKs = {'l': 11, 'q': q, 'g': g, 'X': X, 'Y': Y}
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
        X = self.PKs['X']
        Y = self.PKs['Y']
        g = self.PKs['g']
        group = self.PKs['group']

        Q = self.SKg['Q']
        σ = self.MK['σ']

        member = pair(CTi['ai'], Y) == pair(g, CTi['bi']) and \
            pair(X, CTi['ai']) * pair(X, CTi['bi']) ** hash_Zn(CTi['IDi'], group) == pair(g, CTi['ci'])

        if member:
            D = pair(Q, Up) ** σ
            return D
        else:
            return "Access Denied"

    ###
    #  /DataDcrypt
    ###

    def get_public_params(self):
        return self.PKs

class ConsultantServer(rpyc.Service):
    def __init__(self):
        self.consultant = Consultant(512)

    def exposed_get_public_parameters(self):
        return 10 #self.consultant.PKs

    def get_private_parameters(self):
        return self.consultant.PKs

    def join(self, port):
        pass


if __name__ == "__main__":
    server = ThreadedServer(ConsultantServer, port = 8001)
    server.start()
