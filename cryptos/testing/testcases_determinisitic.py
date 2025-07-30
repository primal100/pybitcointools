import unittest
from cryptos import *

class MyTests(unittest.TestCase):
    def test_bip32_deserialize(self):
        for i in range(0, 10):
            words = entropy_to_words(os.urandom(32))
            # Sample xpub and xprv
            coin = Bitcoin(testnet=False)
            wallet = coin.wallet(words)
            xprv_sample = wallet.keystore.xprv
            xpub_sample = wallet.keystore.xpub

            # For testnet: tpub and tprv
            coin = Bitcoin(testnet=True)
            wallet = coin.wallet(words)
            tprv_sample = wallet.keystore.xprv
            tpub_sample = wallet.keystore.xpub


            # Deserialize
            xpub_deserialized = bip32_deserialize(xpub_sample)
            xprv_deserialized = bip32_deserialize(xprv_sample)
            tpub_deserialized = bip32_deserialize(tpub_sample)
            tprv_deserialized = bip32_deserialize(tprv_sample)

            # Assert checks
            # Check xpub
            assert len(xpub_deserialized[-1]) == 33  # Compressed public key length
            assert xpub_deserialized[-1][0] in [2, 3]  # Must start with 02 or 03

            # Check tpub
            assert len(tpub_deserialized[-1]) == 33
            assert tpub_deserialized[-1][0] in [2, 3]

            # Check xprv - It should have an appended '01' to indicate that it's a compressed private key
            assert xprv_deserialized[-1][-1] == 1

            # Check tprv
            assert tprv_deserialized[-1][-1] == 1

            print("All tests passed!")

    def test_child_derivation_unhardened(self): 

        words = entropy_to_words(os.urandom(32))
        coin = Bitcoin(testnet=True)
        wallet = coin.wallet(words)
        tprv = wallet.keystore.xprv
        tpub = wallet.keystore.xpub

        for i in range(10):
            path = "m/0/{}".format(i)

            child_tprv = bip32_ckd(tprv, path, prefixes=PRIVATE, public=False)
            privkey = bip32_deserialize(child_tprv)[-1]

            child_tpub = bip32_ckd(tpub, path, prefixes=PUBLIC, public=False)
            pubkey = bip32_deserialize(child_tpub)[-1]

            assert(privtopub(privkey) == pubkey)


        coin = Bitcoin(testnet=False)
        wallet = coin.wallet(words)
        xprv = wallet.keystore.xprv
        xpub = wallet.keystore.xpub
        
        for i in range(10):       
            path = "m/0/{}".format(i)
            
            child_xprv = bip32_ckd(xprv, path, prefixes=PRIVATE, public=False)   
            privkey = bip32_deserialize(child_xprv)[-1]
            
            child_xpub = bip32_ckd(xpub, path, prefixes=PUBLIC, public=False) 
            pubkey = bip32_deserialize(child_xpub)[-1] 
            
            assert(privtopub(privkey) == pubkey)


