from binascii import hexlify
import unittest

from xpub_stuff import *


class TestMethods(unittest.TestCase):

    M_PUBLIC = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
    M_PRIVATE = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
    M_0H_PUBLIC = 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw'
    M_0H_PRIVATE = 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'
    M_0H_1_PUBLIC = 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'
    M_0H_1_PRIVATE = 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'

    def test_xpub_from_xprv(self):
        expected_public_key = self.M_0H_PUBLIC

        actual_public_key = xpub_from_xprv(self.M_0H_PRIVATE)

        self.assertEqual(expected_public_key, actual_public_key)


    def test_xprv_decomposition(self):
        expected_private_key = b'3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368'
        source_xprv = self.M_0H_1_PRIVATE

        actual_private_key = hexlify(deserialize(source_xprv).key)

        self.assertEqual(expected_private_key, actual_private_key)


    def test_generate_child_xprv(self):
        expected_child = self.M_0H_1_PRIVATE

        actual_child = generate_child_xprv(self.M_0H_PRIVATE)

        self.assertEqual(expected_child, actual_child)


    def test_generate_child_xpub(self):
        xprv = self.M_0H_PRIVATE
        child_xprv = generate_child_xprv(xprv)
        child_xpub = xpub_from_xprv(child_xprv)

        self.assertEqual(child_xpub, self.M_0H_1_PUBLIC)


    def test_second_generate_child_xpub(self):
        xprv = self.M_0H_PRIVATE
        xpub = xpub_from_xprv(xprv)
        child_xpub = generate_child_xpub(xpub)

        self.assertEqual(child_xpub, self.M_0H_1_PUBLIC)


    def test_address_from_uncompressed_public_key(self):
        uncompressed_public_key = '0402a406624211f2abbdc68da3df929f938c3399dd79fac1b51b0e4ad1d26a47aa9f3bc9f3948a19dabb796a2a744aae50367ce38a3e6b60ae7d72159caeb0c102'
        expected_address = '14K1y4Epb341duzDmWsPniLyBh9EVh8jG3'

        actual_address = address_from_public_key(uncompressed_public_key)

        self.assertEqual(actual_address, expected_address)


    def test_address_from_xpub(self):
        expected_address = '19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh'

        actual_address = address_from_xpub(self.M_0H_PUBLIC)

        self.assertEqual(expected_address, actual_address)


    def test_address_from_xprv(self):
        expected_address = '19Q2WoS5hSS6T8GjhK8KZLMgmWaq4neXrh'
        xprv = self.M_0H_PRIVATE

        xpub = xpub_from_xprv(xprv)
        compressed_public_key = hexlify(deserialize(xpub).key)
        actual_address = address_from_public_key(compressed_public_key)

        self.assertEqual(expected_address, actual_address)


if __name__ == '__main__':
    unittest.main()
