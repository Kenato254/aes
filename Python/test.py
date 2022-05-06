from cgi import test
import unittest
from aes import AES

class TestAES(unittest.TestCase):
    def setUp(self) -> None:
        self.test = AES()
        return super().setUp()
    
    def test_encrypt_method(self):
        """Test AES encryption method """
        cipher = self.test.encrypt("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f")
        self.assertEqual(cipher, "69c4e0d86a7b0430d8cdb78070b4c55a")

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

        #! Testing a plaintext that has length greater than 16 but needs padding
        plaintext = "Function consists of multiplying each column of the block with a constant matrix as follow"
        blocks3 = self.test._divideIntoBlocks(plaintext)
        for block in blocks3:
            self.assertEqual(len(block), 16)

    def test_rotWord_method(self):
        """
        ! Function tests proper working of cyclic permutation method
        """
        permutated = self.test._rotWord(["0x09", "0xcf", "0x4f", "0x3c"])
        self.assertListEqual(permutated, ["0xcf", "0x4f", "0x3c", "0x09"])

    def test_subWord_method(self):
        """
        ! Function tests proper working of four-byte substitution using S-Box
        """
        sBoxed = self.test._subWord(["0xcf", "0x4f", "0x3c", "0x09"])
        self.assertListEqual(sBoxed, ["0x8a", "0x84", "0xeb", "0x01"])
    
    def test_rCon_method(self):
        """
        ! Function tests proper working round coeffecient operation
        """
        rConed = self.test._rCon(["0x8a", "0x84", "0xeb", "0x01"], 1)
        self.assertListEqual(rConed, ["0x8b", "0x84", "0xeb", "0x01"])

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
        results = self.test._aXorB(["0x8b", "0x84", "0xeb", "0x01"],   ["0x2b", "0x7e", "0x15", "0x16"])
        self.assertListEqual(results, ["0xa0", "0xfa", "0xfe", "0x17"])
    
    def test_subBytes_method(self):
        """
        ! Function tests proper working of subByte function
        """
        bytesBefore = [
            '0x4f', '0x0e', '0x1c', '0x4f', 
            '0x16', '0x1f', '0x1c', '0x1c', 
            '0x16', '0x0e', '0x01', '0x1a', 
            '0x20', '0x08', '0x1c', '0x31'
        ]
        bytesAfter =  [
            '0x84', '0xab', '0x9c', '0x84', 
            '0x47', '0xc0', '0x9c', '0x9c', 
            '0x47', '0xab', '0x7c', '0xa2', 
            '0xb7', '0x30', '0x9c', '0xc7'
        ]
        results = self.test._subBytes(bytesBefore)
        self.assertListEqual(results, bytesAfter)
    
    def test_shiftRows_method(self):
        """
        ! Function tests proper working of shiftByte function
        """
        bfShift = [
            '0x84', '0xab', '0x9c', '0x84', 
            '0x47', '0xc0', '0x9c', '0x9c', 
            '0x47', '0xab', '0x7c', '0xa2', 
            '0xb7', '0x30', '0x9c', '0xc7'
        ]
        
        afShift = [
            '0x84', '0xc0', '0x7c', '0xc7',
            '0x47', '0xab', '0x9c', '0x84',
            '0x47', '0x30', '0x9c', '0x9c',
            '0xb7', '0xab', '0x9c', '0xa2'
        ]

        result = self.test._shiftRows(bfShift)
        self.assertListEqual(result, afShift)
    
    def test_mixColumnsAdd_method(self):
        """
        ! Functon tests proper working of mixColumns' GF(2^m) Addition
        """
        testData = [['0x92', '0x76', '0x87', '0x3b'], ['0x45', '0x72', '0xf5', '0x89'], ['0x7f', '0x02', '0xbf', '0x08']]
        result = ['0x58', '0x4b', '0xca']
        for i in range(len(testData)):
            self.assertEqual(self.test._mixColumnsAdd(testData[i]), result[i])

    def test_mixColumnsMult_method(self):
        """
        ! Function tests proper working of mixColumns' GF(2^m) Multiplication
        """
        const = [[0x02, 0x03, 0x01, 0x01], [0x01, 0x02, 0x03, 0x01], [0x01, 0x01, 0x02, 0x03]]
        data = [['0x49', '0xdb', '0x87', '0x3b'], ['0x45', '0x39', '0x53', '0x89',], ['0x7f', '0x02', '0xd2', '0xf1']]
        result = [['0x92', '0x76', '0x87', '0x3b'], ['0x45', '0x72', '0xf5', '0x89'], ['0x7f', '0x02', '0xbf', '0x08']]
        for each in range(len(const)):
            for c, d, r in zip(const[each], data[each], result[each]):
                self.assertEqual(self.test._mixColumnsMult(d, c), r)

    def test_mixColumn_method(self):
        """
        ! Function tests proper mixColumns method functionality
        """
        testData = [
            '0xd4', '0xbf', '0x5d', '0x30', 
            '0xe0', '0xb4', '0x52', '0xae', 
            '0xb8', '0x41', '0x11', '0xf1', 
            '0x1e', '0x27', '0x98', '0xe5'
        ]

        resultList = [
            '0x04', '0x66', '0x81', '0xe5', 
            '0xe0', '0xcb', '0x19', '0x9a',
            '0x48', '0xf8', '0xd3', '0x7a',
            '0x28', '0x06', '0x26', '0x4c'
        ]
        result = self.test._mixColumns(testData)
        self.assertListEqual(result, resultList)
    
    def test_invMixColumn_method(self):
        """
        !
        """
        before = [
            "0xbd", "0x6e", "0x7c", "0x3d", 
            "0xf2", "0xb5", "0x77", "0x9e", 
            "0x0b", "0x61", "0x21", "0x6e", 
            "0x8b", "0x10", "0xb6", "0x89",
        ]

        after = [
            "0x47", "0x73", "0xb9", "0x1f", 
            "0xf7", "0x2f", "0x35", "0x43", 
            "0x61", "0xcb", "0x01", "0x8e", 
            "0xa1", "0xe6", "0xcf", "0x2c",
        ]

        result = self.test._invMixColumns(before)
        self.assertListEqual(result, after)

    def tearDown(self) -> None:
        self.test
        return super().tearDown()