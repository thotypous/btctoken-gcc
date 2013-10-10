from electrum import bitcoin
from nacl.secret import SecretBox
import sys, scrypt

asecret = sys.argv[1]
password = sys.argv[2]

secret = bitcoin.ASecretToSecret(asecret)
assert(secret)
pkey = bitcoin.regenerate_key(asecret)
compressed = bitcoin.is_compressed(asecret)
public_key = bitcoin.GetPubKey(pkey.pubkey, compressed)
h160 = bitcoin.hash_160(public_key)
assert(len(h160) == 0x14)
address = bitcoin.hash_160_to_bc_address(h160)

rand_data = open('/dev/random','rb').read(2*24)
salt  = rand_data[:24]
nonce = rand_data[24:48]

encryption_key = scrypt.hash(password, salt, N=64, r=8, p=1, buflen=32)
box = SecretBox(encryption_key)
encrypted_secret = box.encrypt(secret, nonce)

script_pubkey = bytearray([0x19, 0x76, 0xa9, 0x14]) + bytearray(h160) + bytearray([0x88, 0xac])
ciphertext = bytearray(16 * [0x00]) + bytearray(encrypted_secret.ciphertext)
carray = lambda a: ', '.join(['0x%02x'%x for x in bytearray(a)])

print("// Bitcoin keys for address %s" % address)
print("static const uint8_t my_scriptPubKey[] = { %s };" % carray(script_pubkey))
print("static const uint8_t my_pubkey[] = { %s };" % carray(public_key))
print("static const uint8_t my_enc_salt[] = { %s };" % carray(salt))
print("static const uint8_t my_enc_nonce[] = { %s };" % carray(nonce))
print("static const uint8_t my_enc_privkey[] = { %s };" % carray(ciphertext))
