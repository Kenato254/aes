import secrets
import string

class AES:
    def __init__(self, blocksize=128) -> None:
        """
        * Nb -> Number of columns comparing the state (128 bit standard is 4)
        * Nk -> Number of 32 bit words comprising the Cipher key (128 bit standard is 4)
        * Nr -> Number of rounds, which is a function of Nk and Nb (128 bit standard is 4)
        """
        if blocksize == 128:
            self.Nk = 4
            self.Nb = 4
            self.Nr = 10
    
    def encrypt(self, plaintext, key) -> str:
        blocks = self._divideIntoBlocks(plaintext)

        roundKeys = self._getRoundKeys(key) #? Key Expansion

        for block in blocks:
            self._addRoundKey(roundKeys[0], block)
            self._subBytes(block)
            self._shiftRows(block)
            self._mixColumns(block)
            exit()
            # for each in range(8):
        #         self._subBytes(block)
        #         self._shiftRows(block)
        #         self._mixColumns(block)
        #         self._addRoundKey(roundKeys[each], block)
            
        #     self._subBytes(block)
        #     self._shiftRows(block)
        #     self._mixColumns(block)
        #     self._addRoundKey(roundKeys[10-1], block) #? For 128-bit key 

        # ciphertext = self._Reassemble(blocks)
        # return ciphertext
    

    def decrypt(self, ciphertext, key):
        return 

    def _divideIntoBlocks(self, plaintext) -> list:
        """ 
        * Functons must perform the division of the input text into blocks of 128bit (16 bytes)
        * This function operates on two cases; Case 1: Plaintext < 16 bytes Case 2: Plaintext > 16 bytes
        """
        #? Divide plaintext into block of 4 by 4 bytes or 128 bits.  
        blocks = []
        length = len(plaintext) #! length
        innerBlocks = length // 16
        padding = 16 - length if length < 16 else length % 16

        #? Case 1
        if innerBlocks < 1:
            # plaintext += " " * padding #? Padding plaintext to achieve 16 characters string
            #? Padding plaintext to achieve 16 characters string
            plaintext += ''.join(secrets.choice(string.ascii_lowercase + string.digits + string.ascii_uppercase)\
                        for i in range(padding))
            temp = []
            for char in plaintext:
                # temp.append(ord(char))
                temp.append(hex(ord(char))) #? Hexdecimals
                # temp.append(hex(ord(char)).lstrip("0x")) #? Hexdecimals
            blocks.append(temp)
            return blocks
        
        #? Case 2
        if padding > 0:
            # plaintext += " " * padding #? Padding plaintext to achieve 16 characters string
            #? Padding plaintext to achieve 16 characters string
            plaintext += ''.join(secrets.choice(string.ascii_lowercase + string.digits + string.ascii_uppercase)\
                        for i in range(padding))
            innerBlocks = len(plaintext) // 16  
        
        index = 0
        while innerBlocks:
            temp = []
            for char in plaintext[index:index+16]:
                # temp.append(ord(char))
                temp.append(hex(ord(char))) #? Hexdecimals
                # temp.append(hex(ord(char)).lstrip("0x")) #? Hexdecimals

            if len(temp) > 0:
                blocks.append(temp)
                index += 16
                innerBlocks -=1

        return blocks
    
    def _getRoundKeys(self, key) -> None:
        """
        * Functions performs key whitening/ key schedule.The key schedule takes the original 
        * input key (of length 128, 192 or 256 bit) and derives the subkeys used in AES.
        * The number of subkeys is equal to the number rounds plus one, due to the key 
        * needed for key whitening in the first key addition layer. Nr + 1 = 11 subkeys
        """

        if len(key) < 16: #? Padding with random string for 128 bit key encryption
            padding = ''.join(secrets.choice(string.ascii_lowercase + string.digits + string.ascii_uppercase)\
                        for i in range(16 - len(key)))
            key += padding

        word = 4 *[(self.Nr-1)] #?  An array of 4 bytes.

        temp = None
        i = 0
        while i < self.Nk:
            # word[i] = key[4*i] + key[4*i+1] + key[4*i+2] + key[4*i+3] #? First subkey division. Comprising of four words
            # word[i] = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]]
            # word[i] = [ord(key[4*i]), ord(key[4*i+1]), ord(key[4*i+2]), ord(key[4*i+3])]
            # word[i] = [hex(ord(key[4*i])), hex(ord(key[4*i+1])), hex(ord(key[4*i+2])), hex(ord(key[4*i+3]))]

            #? First subkey division. Comprising of four words of hexdecimal string
            word[i] = [hex(ord(key[4*i])), hex(ord(key[4*i+1])), \
                        hex(ord(key[4*i+2])), hex(ord(key[4*i+3]))]
            i += 1   
        i = self.Nk

        while i < self.Nb * (self.Nr+1):
            temp = word[i-1]
            if i % self.Nk == 0:
                temp = self._rCon(self._subWord(self._rotWord(temp)), i//self.Nk)

            elif self.Nk > 6 and i % self.Nk == 4:
                temp = self._subWord(temp)

            word.append(self._aXorB(word[i-self.Nk], temp))
            i +=1
        return word
        
    def _subWord(self, word) -> list:
        """
        * Function used in the Key Expansion routine that takes a four-byte input word and 
        * applies an S-box to each of the four bytes to produce an output word. 
        """
        for w in range(len(word)):
            word[w] = self._lookUpHex(word[w].split("0x")[1])
        return word

    def _rotWord(self, word) -> list:
        """
        * Function used in the Key Expansion routine that takes a four-byte word and performs a cyclic permutation. 
        """
        rotateword = word.pop(0)    
        word.append(rotateword)
        return word
    
    def _rCon(self, word, rcon) -> list:
        """
        * Function XOR a given word with a given rcon
        """
        result = hex(int(word[0], 16) ^ rcon)
        word[0] =  result if len(result) == 4 else self._patchHex(result)
        return word

    def _lookUpHex(self, hexString) -> str:
        """
        * Function maps given hex string to its substitute value on S-Box and then returns it hex string value
        """
        hexString = hex(self._sBox[int("0x"+hexString[0], 16)][int("0x"+hexString[1], 16)])
        if len(hexString) != 4:
            hexString = self._patchHex(hexString)
        return hexString

    def _aXorB(self, list1, list2) -> list:
        """
        * Function takes word1/list1 and word2/list and returns value of [list1 ^ list2]
        """
        temp = []
        for item1, item2 in zip(list1, list2):
            result = hex(int(item2, 16) ^ int(item1, 16))
            if len(result) != 4:
                result = self._patchHex(result)
            temp.append(result)
        return temp
    
    def _patchHex(self, hexString) -> str:
        """
        * Function takes a hex string with a missing zero adds a zero to it, then returns whole value
        """
        return hexString[:2] + "0" + hexString[2:]

    def _addRoundKey(self, key, block) -> list:
        """
        * The key addition layer uses addition operation of Galois Field GF(2^m). These operations are straightforward. 
        * They are achieved by performing standard polynomial addition and substraction.
        """
        for k, v in enumerate(block):
            result = hex(int(v, 16) ^ int(key[k//4], 16))
            if len(result) != 4:
                result = self._patchHex(result)
            block[k] = result
        return block

    def _subBytes(self, block):
        """
        * Functions takes an array of bytes then perform substitution: each byte in the block is replaced by 
        * the corresponding element from the fixed table (S-box).

        """
        return self._subWord(block)

    def _shiftRows(self, block) -> list:
        """
        * Function cyclically shifts the bytes in each row of the block by r bytes to the left, depending on the row number.
        """
        block = [
            block[0], block[5], block[10], block[15], 
            block[4], block[9], block[14], block[3],
            block[8], block[13], block[2], block[7],
            block[12], block[1], block[6], block[11]
        ]
        return block

    def _mixColumns(self, block) -> list:
        """
        * Function consists of multiplying each column of the block with a constant matrix as follows:
        ! Function work in progress
        """
        #? Input 4 bytes i.e newly formed after shiftRow 0, 1, 2, 3
        const = [
            0x02, 0x03, 0x01, 0x01,
            0x01, 0x02, 0x03, 0x01,
            0x01, 0x01, 0x02, 0x03, 
            0x01, 0x01, 0x01, 0x02
        ]
        print(block)
        counter = x = y = 0
        temp = [0, 1, 2, 3]
        while counter < len(block):
            multiplication = []
            for each in range(0, len(block), 4):
                # print(counter, x, y)            
                y = 0 if  y >= 15 else y+1
                # x = if counter < 3 else x+1
                print(each)
            print("=====")
            exit()
            counter +=1
        
        # block = [
        #     block[0], block[5], block[10], block[15], 
        #     block[4], block[9], block[14], block[3],
        #     block[8], block[13], block[2], block[7],
        #     block[12], block[1], block[6], block[11]
        # ]

        return block
    
    def _calcMixColumn(self, bytes1, bytes2):
        """
        * Functions takes two subarray, performs Galois Field Multiplication, then return a result value
        ! Function has a bug
        """
        # GF(2^m) mod p(x) -> Multiplication is done between two coefficients (byte1 & byte2) Overflow is modularated using byte1
        result = hex(int(bytes1, 16) * 2) if bytes2 > 0x01 else hex(int(bytes1, 16) * bytes2)
        if len(result) > 4: #Overflow mod
            result = hex(int(result, 16) ^ int(bytes1, 16))
            if bytes2 == 0x03:
                result = hex(int(result, 16) ^ int(bytes1, 16))
            result = result[:2] + result[3:] # Dropping overflow

        elif len(result) < 4:
            result = self._patchHex(result)

        # Mulitiplication using 0x03 is always modular self(bytes1)
        if len(result) == 4 and bytes2 == 0x03:
                result = hex(int(result, 16) ^ int(bytes1, 16))
        return result

    def _Reassemble(self, blocks) -> str:
        """ 
        * Functons must perform the concantination of blocks of 128bit (16 bytes) into a string of ciphertext
        """
        return

    def _invCipher(self):
        pass

    def _invSubBytes(self, state):
        pass

    def _invShiftRows(self, state):
        pass

    def _invMixColumns(self, state):
        pass

    #? Substitution table
    _sBox = [
        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76], 
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0], 
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15], 
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75], 
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84], 
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf], 
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8], 
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2], 
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73], 
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb], 
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79], 
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08], 
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a], 
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e], 
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf], 
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
    ]

def main():
    aes = AES()
    plaintext = "Function consists of multiplying each column of the block with a constant matrix as follow"
    key = "opyrightSpringer"
    aes.encrypt(plaintext, key)
    # aes.encrypt("hello", "word")
    # aes._invCipher()
# main()
