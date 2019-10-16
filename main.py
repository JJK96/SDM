from typing import List, Dict, Set, Tuple
import charm

class Client:
    """
    This is the client
    """

    def __init__(self):
        pass

    def make_trapdoor(self,Lp, PKs, SKg):
        pass
    
    def search_indices(self,TLp,IR, PKs):
        pass
    
    def index_gen(self, R, PKs, SKg):
        pass

    def data_encrypt(self, R, PKs, SKg, IR):
        pass

    def data_aux(self, C, CTi, PKs):
        pass

    def send_file(self, file):
        pass
    
    def get_file(self, CTi, PKs, TLp, ):
        pass
    
    def get_decryption_key(self, Up, CTi):
        pass
    
    def mem_decrypt(C, D, PKs, SKg, v):
        pass


class Consultant(Client):
    """ 
    This is also the group manager (GM)
    """

    def __init__(self):
        pass
    
    def system_setup(self, tau):
        
        pass

    def group_auth(self, g, PKs, MKg):
        pass

    def member_join(self, g, Ms, PKs, MKg):
        pass

    def member_leave(self, g, Ms, PKs):
        pass

    def get_decryption_key(self, Up, CTi, PKs, SKg, MK):
        pass

    def member_decrypt(self, C, D, PKs, SKg, v):
        pass

class Server:
    """ 
    This is the server (honest but curious)
    """

    def __init__(self, pp: Tuple[int, int, int, int, int]):
        """
        Initialize the server class with arguments ...
        """
        pass
    
    def add_file(self, file):
        """
        Add a client-generated index and encrypted file to the server
        """
        pass

    def member_check(self, CTi, PKs):
        """
        Check the membership of a certificate
        """
        pass

    def search_index(self, TLp, IR, PKs):
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
