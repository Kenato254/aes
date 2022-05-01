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

        #! Testing a plaintext that has length greater than 16 but needs padding
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
    
    def test_rCon_method(self):
        """
        ! Function tests proper working round coeffecient operation
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

    def test_mixColumn_method(self):
        resultList = [
            '0x58', '0x4d', '0xca', '0xf1', 
            '0x1b', '0x4b', '0x5a', '0xac',
            '0xdb', '0xe7', '0xca', '0xa8',
            '0x1b', '0x6b', '0xb0', '0xe5'
        ]
        testData = [
            '0x49', '0xdb', '0x87', '0x3b', 
            '0x45', '0x39', '0x53', '0x89',
            '0x7f', '0x02', '0xd2', '0xf1',
            '0x77', '0xde', '0x96', '0x1a'
        ]
        # result = self.test._mixColumns(testData)
        # self.assertListEqual(result, ['0x92', '0x6d', '0x87', '0x3b'])
    
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

    def tearDown(self) -> None:
        self.test
        return super().tearDown()
