from binascii import unhexlify
from electrum.util import user_dir
import os, struct
f = open('test.in','wb')
def w(packet):
    f.write(packet.ljust(64,'\x00'))
tx1 = '01000000031df791e89f6a29d84b2996111281295e5438f54abd18f6c754a0d67c8cc24a4e0000000000ffffffffe6120e7d8efd64cdcd55c68e08c0fefae42ef20caf8ba91887acf2903068e3f40100000000ffffffff327996154d3884c3b933163660a08f8f6fd30c466f460351d34324f89765bc1e0100000000ffffffff0280969800000000001976a914959e401d68063f77632787e7acba00098e3c346988ac37fb1600000000001976a914b07e163be63d633ac3cc0c93eb853b684cd279cd88ac00000000'
tx2 = '01000000031df791e89f6a29d84b2996111281295e5438f54abd18f6c754a0d67c8cc24a4e000000008c493046022100dedfdd9e76925aa949c693d5bbd5ecd6fe0b7b868dc7f8b5caaf7cf52d7171c9022100b447085dd1da3be0aed2986c5d062b232fb32d4f734e90a07f4090bc682ae7a00141042d2a61ff964c566605a4a4e65df757b3136b1ca5e3166fa08d8e0397a3a196b75997387118c7df30235c4fa76f619168d274032470a24582320687b7202b032bffffffffe6120e7d8efd64cdcd55c68e08c0fefae42ef20caf8ba91887acf2903068e3f4010000008b483045022065c9a6c8e253d571db3f071ad7b28656787c8691f136900ab7f3156f64760863022100ab0b1d0f0c64b447fd84551530737121319a70c9507e7930cfa176292bf7c2620141042d2a61ff964c566605a4a4e65df757b3136b1ca5e3166fa08d8e0397a3a196b75997387118c7df30235c4fa76f619168d274032470a24582320687b7202b032bffffffff327996154d3884c3b933163660a08f8f6fd30c466f460351d34324f89765bc1e010000008b483045022054b37924f90e8c5ec66845677d1e826081136f056d45a08a3ac98b251d5e3b9f0221008711cd4c626d6474b51a9d5478b33199998fdb1ff418c491fc292f6ab044c6cd0141042d2a61ff964c566605a4a4e65df757b3136b1ca5e3166fa08d8e0397a3a196b75997387118c7df30235c4fa76f619168d274032470a24582320687b7202b032bffffffff0280969800000000001976a914959e401d68063f77632787e7acba00098e3c346988ac37fb1600000000001976a914b07e163be63d633ac3cc0c93eb853b684cd279cd88ac00000000'
tx3 = '010000000138b3962f818247d6dc76f0817b0bd3af9b3b7b336afb40e8c112268e12ccfddf000000006c49304602210099efb1673fae8fbc5f10be02f36c28ac4a3b7a4be803652b27d5b7eeaee012ed022100d33e9d62c0606944051079c6914cac0d51827efc0ec54fde5a695c54ff4f502101210321e0fe78badf38003223d5e08ccc7b931f13f7649c23f1d8bc96eb267f77ca5affffffff02b51e7f69000000001976a914a5c17e3ee04d7a0940b45fd92791a473b1cca38688ac404b4c00000000001976a914b07e163be63d633ac3cc0c93eb853b684cd279cd88ac00000000'
for tx in [tx1, tx3]:
    tx = unhexlify(tx)
    w('RAWTXlen'+struct.pack('<H',len(tx)))
    while len(tx):
        w(tx[:64])
        tx = tx[64:]
    
merkle = [u'b79bd5e0c650d128982b1ee2465eb229473785ad02cb6981629822b6b821c9fc', u'f931b00962f7d4f17043cf6e413a613dcb605309cfc40718550e31595abb8d16', u'b2435f2c51a057974987259326d89389e1a5a17f41798ee11470d474d8e7d7d0', u'dfcb653476840ec41078083818be0e2760bde00baab05f4023449ed1eca0f443', u'e8a6b506105ac3c31ea1701795ee3024dae5c99ab58c624cb21820c6796610ea', u'ad701e192ae194411814056f891612dd9150815c1384532240e9040b3b177b06', u'75b4f1158509b0ef3b860a742abb1994f998ac0297aa076435d2e18bc0a77fc1', u'7242cf9d1c358b3843d13451ef7717080bb5055ab3e4cd377b5ea921945bfe2b', u'87c9d49e84e8593304c7997069fa31a0a78ba6b38e67d6a0c26500b60b0bca2e', u'd69951323e3a611282b06865d67508dbac21bd1137f850f194f90da14b47630f']
pos = 192
for i,x in enumerate(merkle):
    w('MerkleNode'+chr((pos >> i) & 1)+x.decode('hex')[::-1])
w('MerkleNode\xff')

blk = 252125
hf = open(os.path.join(user_dir(), 'blockchain_headers'), 'rb')
hf.seek(blk * 80)
for i in xrange(200):
    hdr = hf.read(80)
    if hdr == '':
        break
    w('Blk1'+hdr[:36])
    w('Blk2'+hdr[36:])

f.close()
