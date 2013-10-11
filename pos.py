import struct, time, thread, sys, socket, os
from binascii import unhexlify, hexlify
from decimal import Decimal
import pyudev
from electrum import Wallet, Interface, WalletVerifier, SimpleConfig, WalletSynchronizer, Transaction, bitcoin, util

dest_addr = '1Ee7G1y5odBa93CTtfDgFxcxQHmiwcYRNw'
tx_amount = Decimal('0.1')
assert bitcoin.is_valid(dest_addr)

def find_usbid(dev):
    """Walk pyudev device parents until USB idVendor and idProduct
       informations are found"""
    ids = ['idVendor', 'idProduct']
    while dev:
        attr = dev.attributes
        if False not in [x in attr for x in ids]:
            return tuple([int(attr[x], 16) for x in ids])
        dev = dev.parent

def wait_dev(vendor, product, subsystem='hidraw'):
    """Wait for a device with the supplied USB vendor and product IDs
       to be attached and identified by a given subsystem.
       Returns a pyudev device object."""
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem)
    monitor.start()
    for dev in iter(monitor.poll, None):
        if dev.action == 'add':
            usbid = find_usbid(dev)
            if not usbid:
                print('Could not recognize USB ID for device %s' % dev.device_path)
                continue
            print('USB device %04x:%04x plugged' % usbid)
            if usbid == (vendor, product):
                print('USB ID matches the expected one')
                return dev

class BTCToken:
    def __init__(self):
        print 'waiting for the device to be plugged'
        udev_dev = wait_dev(0xffff, 0x0bad)
        self.dev = open(udev_dev.device_node, 'r+b', buffering=0)
    def send(self, packet):
        print 'send:', repr(packet)
        self.dev.write('\x00' + packet.ljust(64, '\x00'))
    def recv(self):
        packet = self.dev.read(64)
        print 'recv:', repr(packet)
        return packet
    def ask_pubkey(self):
        self.send('BTCToken')
        packet = self.recv()
        assert(packet.startswith('Yes I am'))
        size, = struct.unpack('<H', packet[8:10])
        pubkey = ''
        while size > 0:
            packet = self.recv()
            pubkey += packet[:min(len(packet), size)]
            size -= len(packet)
        return pubkey
    def send_tx(self, tx):
        self.send('RAWTXlen'+struct.pack('<H',len(tx)))
        while len(tx):
            self.send(tx[:64])
            tx = tx[64:]
    def recv_ok(self):
        assert(self.recv().startswith('OK'))
    def send_sameaddr(self, idx):
        self.send('SameAddr'+struct.pack('<B',idx))
    def send_thirdparty(self):
        self.send('ThirdPty')
    def send_merkle(self, merkle, pos):
        for i,x in enumerate(merkle):
            self.send('MerkleNode'+chr((pos >> i) & 1)+x.decode('hex')[::-1])
        self.send('MerkleNode\xff')
    def send_blocks(self, verifier, blk):
        while True:
            hdr = verifier.header_to_string(verifier.read_header(blk))
            print 'blk #', blk, hdr
            hdr = unhexlify(hdr)
            blk += 1
            self.send('Blk1'+hdr[:36])
            self.send('Blk2'+hdr[36:])
            recved = self.recv()
            if recved.startswith('Trusted'):
                break
            assert(recved.startswith('MoreData'))
    def recv_dbg(self, num_dbg):
        for i in xrange(num_dbg):
            print repr(self.recv())

btctoken = BTCToken()
orig_pubkey = btctoken.ask_pubkey()
orig_addr = bitcoin.public_key_to_bc_address(orig_pubkey)
print 'Costumer bitcoin address:', orig_addr

interface = Interface({'server':'electrum.no-ip.org:50002:s'})
interface.start()

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
btctoken.send_tx(unhexlify(raw_tx.raw))
btctoken.recv_ok()
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
        btctoken.send_sameaddr(idx_same)
        btctoken.send_tx(unhexlify(tx.raw))
        btctoken.recv_ok()
    else:
        print 'input tx signed by third parties'
        print 'raw tx:',tx.raw
        print repr(tx.deserialize())
        tx_height, _ = verifier.get_txpos(tx_hash)
        res = interface.synchronous_get([ ('blockchain.transaction.get_merkle',[tx_hash,tx_height]) ])[0]
        btctoken.send_thirdparty()
        btctoken.send_tx(unhexlify(tx.raw))
        print 'sending merkle tree'
        print repr((res['merkle'], tx_hash, res['pos']))
        btctoken.send_merkle(res['merkle'], res['pos'])
        print 'sending headers starting from blk %d' % tx_height
        btctoken.send_blocks(verifier, tx_height)
        btctoken.recv_ok()
    print '\n\n'

print 'debugging info'
btctoken.recv_dbg(3)
print '\n\n'

for i in range(len(raw_tx.inputs)):
    tx_for_sig = raw_tx.serialize( raw_tx.inputs, raw_tx.outputs, for_sig = i )
    print 'tx_for_sig:', tx_for_sig
    tx_for_sig_hash = bitcoin.Hash(unhexlify(tx_for_sig))
    print 'tx_for_sig_hash:', hexlify(tx_for_sig_hash)
print '\n\n'

# get signatures from device
print 'should now get', len(raw_tx.inputs), 'signatures'
for i in xrange(len(raw_tx.inputs)):
    print 'sig:', hexlify(btctoken.recv())
# broadcast to network using wallet.sendtx(Transaction(hex_string))
