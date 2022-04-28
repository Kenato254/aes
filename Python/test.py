import json
import unittest
from aes import AES

class TestAES(unittest.TestCase):
    def setUp(self) -> None:
        self.test = AES()
        return super().setUp()
    
    # def test_encryption_method(self):
    #     self.test.encrypt("Hello", "word")
    
    def test_divideIntoBlocks_method(self):
        """
        ! Function tests proper working of AES._divideIntoBlock method
        """
        #? Testing a plaintext that needs padding
        blocks = self.test._divideIntoBlocks("Hello")
        self.assertEqual(len(blocks[0]), 16)

        #? Testing plainteext that doesn't need padding
        blocks2 = self.test._divideIntoBlocks("Hello world!!!!!")
        self.assertEqual(len(blocks2[0]), 16)

        #? Testing a plaintext that has length greater than 16 but needs padding
        plaintext = "Function consists of multiplying each column of the block with a constant matrix as follow"
        blocks3 = self.test._divideIntoBlocks(plaintext)
        for block in blocks3:
            self.assertEqual(len(block), 16)

    def test_rotWord_method(self):
        """
        ! Function tests proper working of cyclic permutation method
        """
        permutated = self.test._rotWord(['0x6e', '0xc5', '0x45', '0xa5'])
        self.assertListEqual(permutated, ['0xc5', '0x45', '0xa5', '0x6e'])

    def test_subWord_method(self):
        """
        ! Function tests proper working of four-byte substitution using S-Box
        """
        sBoxed = self.test._subWord(['0xc5', '0x45', '0xa5', '0x6e'])
        self.assertListEqual(sBoxed, ['0xa6', '0x6e', '0x06', '0x9f'])

        with open("testWords.json", 'r') as blocks:
            myData = json.loads(blocks.read())

    
    def test_rCon_method(self):
        """
        ! Function tests proper working round coeffecient operations
        """
        rConed = self.test._rCon(["0x0c", "0x48", "0x99", "0x66"], 1)
        self.assertListEqual(rConed, ["0x0d", "0x48", "0x99", "0x66"])

    def test_lookUpHex_method(self):
        """
        ! Function tests proper mapping of a given hex with S-Box
        """
        hex = self.test._lookUpHex('a5')
        self.assertEqual(hex, '0x06')

    def test_aXorB_method(self):
        """
        ! Function test proper working of XOR function
        """
        results = self.test._aXorB(["0x6f", "0x70", "0x79", "0x72"],   ["0x21", "0x91", "0xea", "0xfc"])
        self.assertListEqual(results, ["0x4e", "0xe1", "0x93", "0x8e"])
        

    def tearDown(self) -> None:
        self.test
        return super().tearDown()
