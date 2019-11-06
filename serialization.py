import copy
from charm.toolbox.pairinggroup import PairingGroup

def serialize_PKs(PKs):
    PKs = copy.copy(PKs)
    for k in ['g', 'X', 'Y']:
        PKs[k] = PKs['group'].serialize(PKs[k])
    return PKs

def deserialize_PKs(_PKs):
    PKs = {}
    PKs['group'] = PairingGroup(_PKs['curve'], secparam=_PKs['secparam'])
    for k in ['g', 'X', 'Y']:
        PKs[k] = PKs['group'].deserialize(_PKs[k])
    for k in ['l', 'q']:
        PKs[k] = _PKs[k]
    return PKs

def serialize_SKg(SKg, PKs):
    SKg = copy.copy(SKg)
    for k in ['α', 'P', 'Pp', 'Q', 'Qp']:
        SKg[k] = PKs['group'].serialize(SKg[k])
    return SKg

def deserialize_SKg(_SKg, PKs):
    SKg = {}
    for k in ['α', 'P', 'Pp', 'Q', 'Qp']:
        SKg[k] = PKs['group'].deserialize(_SKg[k])
    return SKg

def serialize_CTi(CTi, PKs):
    CTi = copy.copy(CTi)
    for k in ['ai', 'bi', 'ci']:
        CTi[k] = PKs['group'].serialize(CTi[k])
    return CTi

def deserialize_CTi(_CTi, PKs):
    CTi = {}
    for k in ['ai', 'bi', 'ci']:
        CTi[k] = PKs['group'].deserialize(_CTi[k])
    CTi['IDi'] = _CTi['IDi']
    return CTi

def serialize_trapdoor(trapdoor, PKs):
    group = PKs['group']
    return [group.serialize(x) for x in trapdoor]

def deserialize_trapdoor(trapdoor, PKs):
    group = PKs['group']
    return [group.deserialize(x) for x in trapdoor]
