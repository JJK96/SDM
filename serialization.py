import copy

def serialize_PKs(PKs):
    PKs = copy.copy(PKs)
    for k in ['g', 'X', 'Y']:
        PKs[k] = PKs['group'].serialize(PKs[k])
    return PKs

def deserialize_PKs(PKs):
    for k in ['g', 'X', 'Y']:
        PKs[k] = PKs['group'].deserialize(PKs[k])
    return PKs

def serialize_SKg(SKg, PKs):
    SKg = copy.copy(SKg)
    for k in ['α', 'P', 'Pp', 'Q', 'Qp']:
        SKg[k] = PKs['group'].serialize(SKg[k])
    return SKg

def deserialize_SKg(SKg, PKs):
    for k in ['α', 'P', 'Pp', 'Q', 'Qp']:
        SKg[k] = PKs['group'].deserialize(SKg[k])
    return SKg

def serialize_CTi(CTi, PKs):
    CTi = copy.copy(CTi)
    for k in ['ai', 'bi', 'ci']:
        CTi[k] = PKs['group'].serialize(CTi[k])
    return CTi

def deserialize_CTi(CTi, PKs):
    for k in ['ai', 'bi', 'ci']:
        CTi[k] = PKs['group'].deserialize(CTi[k])
    return CTi
