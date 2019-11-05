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

def serialize_SKg(SKg):
    SKg = copy.copy(PKs)
