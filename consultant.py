from typing import List, Dict, Set, Tuple, Callable
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair
from funcs import *
import rpyc
import copy
from rpyc.utils.server import ThreadedServer
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
from socket import socket
import traceback
import config
from serialization import *

#DEBUG
import code

class ConsultantClient():
    def __init__(self, ip, port, id):
        self.ip = ip
        self.port = port
        self.id = id
        self.conn = rpyc.connect(ip, port, config=config.config)

class Consultant():
    """ 
    This is also the group manager (GM)
    """

    def __init__(self, τ):
        print('init')
        self.τ = τ
        self.system_setup(τ)
        self.G = {}
 
    def connect_server(self):
        self.server = rpyc.connect(config.SERVER_IP, config.SERVER_PORT, config=config.config)

    def system_setup(self, τ):
        """
        Instantiates the scheme. Has as inputs:
        o Security parameter `τ`

        This function is executed by the GM, and outputs the system public key `PKs`,
        the group secret key `SKg` for all group members and the master key MK for the GM.
        """
        curve = 'SS512'
        group = PairingGroup(curve, secparam=τ)
        g, P, Q = [group.random(G1) for _ in range(3)]
        q = group.order()
        α, x, y, λ, σ = [num_Zn_star_not_one(q, group.random, ZR) for _ in range(5)]
        X = g ** x
        Y = g ** y
        Pp = P ** λ
        Qp = Q ** (λ - σ)
        self.PKs = {'l': 4, 'curve':curve, 'secparam':τ, 'group':group, 'q': q, 'g': g, 'X': X, 'Y': Y}
        self.SKg = {'α': α, 'P': P, 'Pp': Pp, 'Q': Q, 'Qp': Qp}
        self.MK = {'x': x, 'y': y, 'λ': λ, 'σ': σ}
        self.t = 1
        # a = pair(g1**2, g2**3)
        # b = pair(g1, g2) ** 6
        # group.init(ZR, 10)
        # code.interact(local=dict(globals(), **locals()))

    ###
    #  AuthCodGen
    #  Generates the group membership certificates
    ###

    def member_join(self, M):
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
        group = self.PKs['group']
        q = self.PKs['q']
        X = self.PKs['X']

        x = self.MK['x']
        y = self.MK['y']

        if M.id not in self.G:
            print(self.G.keys())
            print(M.id)
            ## Step 1
            t = num_Zn_star_not_one(q, group.random, ZR)
            self.PKs['X'] = X ** t
            self.t *= t
            to_delete = []
            for id, member in self.G.items():
                print("sending to old members")
                try:
                    member.conn.root.update_certificate(group.serialize(t))
                except (BrokenPipeError, EOFError):
                    # member left
                    to_delete.append(id)
            for id in to_delete:
                del self.G[id]
            if not hasattr(self, 'server'):
                self.connect_server()
            self.server.root.update_public_key(group.serialize(t))

            ## Step 2
            ai = group.random(G1)
            bi = ai ** y
            ci = ai ** (self.t * (x + hash_Zn(M.id, group) * x * y))

            CTi = {'IDi': M.id, 'ai': ai, 'bi': bi, 'ci': ci}
            M.CTi = CTi
            print("sending CTi")
            
            # Add the new members to the member group
            self.G[M.id] = M

        M.conn.root.add_certificate(serialize_CTi(M.CTi, self.PKs))
        
        ## Step 3: let old members update ci, we do this already in member.update_certificate

        ## Step 4: new members keep CTi secret!


    def member_leave(self, M):
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
        t = group.serialize(t)
        del self.G[M.id]
        for member in self.G.values():
            member.conn.root.update_certificate(t)
        if not hasattr(self, 'server'):
            self.connect_server()
        self.server.root.update_public_key(t)
        
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
            raise Exception("Access Denied")

    ###
    #  /DataDcrypt
    ###

    def get_public_params(self):
        return self.PKs

class ConsultantServer(rpyc.Service):
    def __init__(self):
        self.consultant = Consultant(512)

    def on_connect(self, conn):
        self.ip, port = socket.getpeername(conn._channel.stream.sock)
        print(self.ip, port)

    def exposed_get_public_parameters(self):
        print("get public parameters")
        return serialize_PKs(self.consultant.PKs)

    def exposed_join(self, port, id):
        print("join")
        client = self.consultant.G.get(id, ConsultantClient(self.ip, port, id))
        try:
            self.consultant.member_join(client)
        except Exception:
            traceback.print_exc()
        SKg = serialize_SKg(self.consultant.SKg, self.consultant.PKs)
        return SKg

    def exposed_leave(self, id):
        print("leave")
        member = self.consultant.G[id]
        assert not member is None
        self.consultant.member_leave(member)

    def exposed_get_decryption_key(self, Up, CTi):
        print("get decryption key")
        PKs = self.consultant.PKs
        CTi = deserialize_CTi(CTi, PKs)
        Up = PKs['group'].deserialize(Up)
        D = self.consultant.get_decryption_key(Up, CTi)
        return PKs['group'].serialize(D)

if __name__ == "__main__":
    server = ThreadedServer(ConsultantServer(), port = 8001, protocol_config=config.config)
    server.start() 
# c = ConsultantServer()
# c.exposed_get_public_parameters()
