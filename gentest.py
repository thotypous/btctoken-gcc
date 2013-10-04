from binascii import unhexlify
import struct
f = open('test.in','wb')
tx = '01000000031df791e89f6a29d84b2996111281295e5438f54abd18f6c754a0d67c8cc24a4e0000000000ffffffffe6120e7d8efd64cdcd55c68e08c0fefae42ef20caf8ba91887acf2903068e3f40100000000ffffffff327996154d3884c3b933163660a08f8f6fd30c466f460351d34324f89765bc1e0100000000ffffffff0280969800000000001976a914959e401d68063f77632787e7acba00098e3c346988ac37fb1600000000001976a914b07e163be63d633ac3cc0c93eb853b684cd279cd88ac00000000'
tx = unhexlify(tx)
packet = 'RAWTXlen'+struct.pack('<H',len(tx))
f.write(packet.ljust(64,'\x00'))
while len(tx):
    packet = tx[:64]
    f.write(packet.ljust(64,'\x00'))
    tx = tx[64:]
f.close()
