import os

import rpyc
from charm.toolbox.pairinggroup import GT, pair, G1
from charm.core.math.pairing import serialize, deserialize
import Crypto

from funcs import *
from rpyc.utils.server import ThreadedServer  # or ForkingServer
import config
import json
import base64
from serialization import *
from errors import *

FILE_DIRECTORY = 'documents'


class Server(rpyc.Service):
    """
    This is the server (honest but curious)
    """

    def __init__(self, _PKs, _consultant_public_key):
        """
        The constructor of the server object
        :param _PKs: The system's public parameters
        :param _consultant_public_key: The public key of the systems consultant
        """
        self.PKs = _PKs
        self.file_directory = FILE_DIRECTORY
        self._create_documents_folder()
        self.client_public_keys = {}
        self.consultant_public_key = _consultant_public_key

    def _create_documents_folder(self):
        """
        Helper function to create the directory where the files need to be stored
        """
        if not os.path.exists(self.file_directory):
            os.makedirs(self.file_directory)

    def exposed_update_public_key(self, t):
        t = self.PKs['group'].deserialize(t)
        self.PKs['X'] = self.PKs['X'] ** t

    def exposed_add_file(self, IR, file, client_id):
        """
        Add a client-generated index and encrypted file to the server
        :param IR: The searchable indexes
        :param file: The file object, containing U, V, Er, and signature
        :param client_id: The client id for which the file needs to be added
        """

        U, V, Er, signature = file
        IR = [base64.b64encode(x).decode('ascii') for x in IR]

        if client_id not in self.client_public_keys.keys():
            raise InputError('Client ID is not found in the server\'s list of clients')

        if not (verify_message(self.client_public_keys[client_id], Er, signature) or verify_message(self.consultant_public_key, Er, signature)):
            raise InputError('The signature does not match the client ID\'s public key or the consultant\'s public key')

        file_to_save = {
            'client_id': client_id,
            'U': base64.b64encode(U).decode('ascii'),
            'V': base64.b64encode(V).decode('ascii'),
            'IR': IR,
            'Er': base64.b64encode(Er).decode('ascii'),
        }

        file_name = self.file_directory + os.path.sep + str(len(next(os.walk(FILE_DIRECTORY))[2])) + '.json'
        json.dump(file_to_save, open(file_name, 'w'), indent=4)

    def exposed_add_client(self, client_id: int, public_key: bytes) -> bool:
        """
        Add the public key for a client to the list of public keys of the server
        :param client_id: The client to add the public key from
        :param public_key: The public key to add
        :return: True if the client_id is not available yet
        """
        public_key = deserialize_public_key(public_key)

        if client_id not in self.client_public_keys:
            self.client_public_keys[client_id] = public_key
            return True
        else:
            return False
    ###
    #  DataQuery
    #  Retrieves the encrypted data which contains specific keywords
    ###

    def member_check(self, CTi):
        """
        Check the membership of a certificate
        :param CTi: Membership Certificate
        :return: either Yes for access granted, or Access Denied to terminate the protocol
        """
        X = self.PKs['X']
        Y = self.PKs['Y']
        g = self.PKs['g']
        group = self.PKs['group']
        CTi = deserialize_CTi(CTi, self.PKs)
        member = pair(CTi['ai'], Y) == pair(g, CTi['bi']) and \
                 pair(X, CTi['ai']) * pair(X, CTi['bi']) ** hash_Zn(CTi['IDi'], group) == pair(g, CTi['ci'])
        return member

    def _test(self, TLp: List[pairing.pc_element], IL: List[pairing.pc_element]) -> bool:
        """
        Test whether the index matches the trapdoor
        :param TLp: Trapdoor
        :param IL: Secure index
        :return: True if the index matches the trapdoor
        """
        assert len(TLp) == len(IL), "Length of trapdoor and index do not match!"

        PKs = self.PKs

        V = PKs['group'].pair_prod(TLp, IL)
        return V == PKs['group'].init(GT, 1)

    def exposed_search_index(self, TLp, CTi, trapdoor_signature):
        """
        Scan all secure indexes against the trapdoor
        :param TLp: Trapdoor
        :param CTi: Membership certificate
        :param trapdoor_signature: Signature of the trapdoor
        :return: Encrypted data `E(R)` for the member when the data includes the searched keywords or "No Data Matched"
        for the member when the data does not contain the keywords
        """
        TLp = deserialize_trapdoor(TLp, self.PKs)

        if self.member_check(CTi):
            result = []

            for IR, file, client_id in self._load_all_ir_and_files():
                IR = deserialize_IL(IR, self.PKs)
                if ((client_id == CTi['IDi'] and verify_message(self.client_public_keys[CTi['IDi']], TLp, trapdoor_signature)) or \
                        verify_message(self.consultant_public_key, TLp, trapdoor_signature)) and \
                        self._test(TLp, IR):
                    result.append(file)

            return result

        else:
            return config.ACCESS_DENIED

    def _load_all_ir_and_files(self):
        """
        Helper function to load all the files that are stored on the server
        :return: List of all the files as tuples (IR, file)
        """
        result = []
        files = next(os.walk(self.file_directory))[2]
        for file_name in files:
            data = json.load(open(os.path.join(self.file_directory, file_name)))
            client_id = data['client_id']
            IR = [base64.b64decode(x.encode('ascii')) for x in data['IR']]

            U = base64.b64decode(data['U'].encode('ascii'))
            V = base64.b64decode(data['V'].encode('ascii'))
            Er = base64.b64decode(data['Er'].encode('ascii'))
            file = (U, V, Er)

            result.append((IR, file, client_id))

        return result


if __name__ == '__main__':
    consultant = rpyc.connect(config.CONSULTANT_IP, config.CONSULTANT_PORT, config=config.config)
    PKs = consultant.root.get_public_parameters()
    consultant_public_key = deserialize_public_key(consultant.root.get_public_key())
    PKs = deserialize_PKs(PKs)
    server = ThreadedServer(Server(PKs, consultant_public_key), port=config.SERVER_PORT, protocol_config=config.config)
    server.start()
