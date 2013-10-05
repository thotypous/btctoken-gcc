import time, thread, sys, socket, os
from binascii import unhexlify, hexlify
from decimal import Decimal
import traceback
from electrum import Wallet, Interface, WalletVerifier, SimpleConfig, WalletSynchronizer, Transaction, bitcoin, util

dest_addr = '1Ee7G1y5odBa93CTtfDgFxcxQHmiwcYRNw'
tx_amount = Decimal('0.1')
assert bitcoin.is_valid(dest_addr)

interface = Interface({'server':'electrum.no-ip.org:50002:s'})
interface.start()

orig_pubkey = unhexlify('042d2a61ff964c566605a4a4e65df757b3136b1ca5e3166fa08d8e0397a3a196b75997387118c7df30235c4fa76f619168d274032470a24582320687b7202b032b')
orig_addr = bitcoin.public_key_to_bc_address(orig_pubkey)

wallet_config = SimpleConfig({
    'wallet_path': os.path.join('cache','%s.wallet'%orig_addr)
})
wallet_config.set_key('master_public_key', 'placeholder')
wallet_config.set_key('use_change', False)
wallet_config.set_key('gap_limit', 1)
wallet = Wallet(wallet_config)

class FixedPubKeySequence(object):
    def __init__(self, *args):
        pass
    def get_address(self, sequence):
        if sequence == (0,0):
            return orig_addr
    def get_pubkey(self, sequence, mpk=None):
        if sequence == (0,0):
            return hexlify(orig_pubkey)
    def get_input_info(self, sequence):
        return self.get_address(sequence), None

wallet.SequenceClass = FixedPubKeySequence
wallet.sequences = {}
wallet.sequences[0] = wallet.SequenceClass(None)

wallet.interface = interface
verifier = WalletVerifier(interface, wallet_config)
wallet.set_verifier(verifier)
synchronizer = WalletSynchronizer(wallet, wallet_config)
synchronizer.start()
verifier.start()
wallet.update()

print '\n\n'
print 'balance:', repr(map(util.format_satoshis, wallet.get_balance()))
print '\n\n'

wallet_config.save()

tx_amount = int(tx_amount*Decimal('1e8'))  # from BTC to Satoshi
raw_tx = wallet.mktx([(dest_addr, tx_amount)], None, None, orig_addr, None)
print 'raw tx:', raw_tx.raw
print repr(raw_tx.deserialize())
print '\n\n'

for tx_in in raw_tx.inputs:
    tx_hash = tx_in['tx_hash']
    tx = wallet.transactions.get(tx_hash)
    tx_in_addrs = [i['address'] for i in tx.inputs]
    try: idx_same = tx_in_addrs.index(orig_addr)
    except: idx_same = -1
    if idx_same >= 0:
        print 'input tx signed by same addr #',idx_same
        print 'raw tx:',tx.raw
        print repr(tx.deserialize())
        print '\n\n'
    else:
        print 'input tx signed by third parties'
        print 'raw tx:',tx.raw
        print repr(tx.deserialize())
        tx_height, _ = verifier.get_txpos(tx_hash)
        res = interface.synchronous_get([ ('blockchain.transaction.get_merkle',[tx_hash,tx_height]) ])[0]
        print 'sending merkle tree'
        print repr((res['merkle'], tx_hash, res['pos']))
        print 'sending headers'
        for i in xrange(6):
            hdr = verifier.read_header(tx_height+i)
            print repr(hdr)
            print 'raw block hdr:', verifier.header_to_string(hdr)
            
        print '\n\n'

# get signatures from device
print 'should now get', len(raw_tx.inputs), 'signatures'
# broadcast to network using wallet.sendtx(Transaction(hex_string))
