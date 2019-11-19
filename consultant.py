from typing import List, Dict, Set, Tuple, Callable
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, pair
from funcs import *
import rpyc
import copy
from rpyc.utils.server import ThreadedServer
from rpyc.utils.authenticators import SSLAuthenticator
from socket import socket
import traceback
import config
from serialization import *
import uuid
from client import Client
import threading
import time

#DEBUG
import code

class ConsultantClient():
    def __init__(self, ip, port, id, public_key):
        self.ip = ip
        self.port = port
        self.id = id
        self.public_key = public_key
        self.conn = rpyc.ssl_connect(ip, port, config=config.config, keyfile="cert/consultant/key.pem", certfile="cert/consultant/certificate.pem")

class Consultant(Client):
    """ 
    This is also the group manager (GM)
    """

    def __init__(self, τ):
        print('init')
        self.τ = τ
        self.system_setup(τ)
        self.G = {}
        self.signingkey = gen_signing_key()
        self.id = str(uuid.uuid4())
        self.group_auth()
    
    def create_consultant_user(self):
        self.member_join(self)
 
    def connect_server(self):
        self.server = rpyc.ssl_connect(config.SERVER_IP, config.SERVER_PORT, keyfile="cert/client/key.pem", certfile="cert/client/certificate.pem", config=config.config)

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
        self.PKs = {'l': 21, 'curve':curve, 'secparam':τ, 'group':group, 'q': q, 'g': g, 'X': X, 'Y': Y}
        self.SKg = {'α': α, 'P': P, 'Pp': Pp, 'Q': Q, 'Qp': Qp}
        self.MK = {'x': x, 'y': y, 'λ': λ, 'σ': σ}
        self.t = 1
        self.ts = []
        # a = pair(g1**2, g2**3)
        # b = pair(g1, g2) ** 6
        # group.init(ZR, 10)
        # code.interact(local=dict(globals(), **locals()))

    ###
    #  AuthCodGen
    #  Generates the group membership certificates
    ###

    def group_auth(self):
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
        ai = group.random(G1)
        bi = ai ** y
        ci = ai ** (x + hash_Zn(self.id, group) * x * y)

        self.CTi = {'IDi': self.id, 'ai': ai, 'bi': bi, 'ci': ci}

        ## Step 2: keep CTi secret!

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
            self.CTi['ci'] = self.CTi['ci'] ** t
            self.t *= t
            self.ts.append((time.time(), t))
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
            self.server.root.add_client(M.id, serialize_public_key(M.public_key))

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
        self.CTi['ci'] = self.CTi['ci'] ** t
        self.t *= t
        self.ts.append((time.time(), t))

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
    

    def upload_file(self, file_location, client_id):
        assert self.CTi is not None, "Consultant needs a certificate!"
        assert hasattr(self, 'server'), "Server has not yet been initialized!"

        D = read_file(file_location)
        IR, R, Ed = self.index_gen(D, client_id)
        Ir, Er = self.data_encrypt(R, IR, Ed)
        IrSerialized = serialize_IL(Ir, self.PKs)

        self.server.root.add_file(IrSerialized, serialize_Er(Er, self.PKs), client_id)

    
    def get_files_by_keywords(self, keywords):
        assert self.CTi is not None, "Consultant needs a certificate!"
        assert hasattr(self, 'server'), "Server has not yet been initialized!"

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
            # D = group.deserialize(self.consultant.root.get_decryption_key(group.serialize(Up), CTi_serialized))
            D = self.get_decryption_key(Up, self.CTi)
            Rp, Ed = self.member_decrypt(result, D, ν)
            files.append(decrypt_document(Rp, Ed))
        return files

class ConsultantServer(rpyc.Service):
    def __init__(self):
        self.consultant = Consultant(512)
        self.start_server()

    def on_connect(self, conn):
        self.ip, port = socket.getpeername(conn._channel.stream.sock)
        print(self.ip, port)

    def exposed_get_public_parameters(self):
        print("get public parameters")
        return serialize_PKs(self.consultant.PKs)
    
    def exposed_get_public_key(self):
        print("get public key")
        return serialize_public_key(self.consultant.signingkey.public_key())
    
    def exposed_get_update_t(self, last_update: float):
        update = (time.time(), self.consultant.PKs['group'].init(ZR, 1))
        for (timestamp, t) in filter(lambda x: x[0] > last_update, self.consultant.ts):
            update = (timestamp, update[1] * t)
        update = (update[0], self.consultant.PKs['group'].serialize(update[1]))
        return update

    def exposed_join(self, port, id, public_key: bytes):
        print("join")
        client = self.consultant.G.get(id, ConsultantClient(self.ip, port, id, deserialize_public_key(public_key)))
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
    
    def start_server(self):
        authenticator = SSLAuthenticator("cert/consultant/key.pem", "cert/consultant/certificate.pem")
        server = ThreadedServer(self, port = 8001, protocol_config=config.config, authenticator=authenticator)
        thread = threading.Thread(target=server.start)
        thread.start()

if __name__ == "__main__":
    ConsultantServer()
# c = ConsultantServer()
# c.exposed_get_public_parameters()
