from charm.toolbox.pairinggroup import GT, pair

from funcs import *
from xmlrpc.server import SimpleXMLRPCServer
from xmlrpc.server import SimpleXMLRPCRequestHandler
from xmlrpc.client import ServerProxy


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


if __name__ == '__main__':
    consultant = ServerProxy("http://130.89.180.57:8001/")
    PKs = consultant.get_public_parameters()
    print(PKs)
    server = SimpleXMLRPCServer(('localhost', 8000), requestHandler=SimpleXMLRPCRequestHandler)
    server.register_instance(Server(PKs))
    print("Started serving my functions baby")
    server.serve_forever()
