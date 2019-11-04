import rpyc

conn = rpyc.connect('130.89.180.57', 8001)
print(conn.root.get_public_parameters())
