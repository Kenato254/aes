class AES:
    def __init__(self, blocksize=128) -> None:
        """
        * Nb -> Number of columns comparing the state (128 bit standard is 4)
        * Nk -> Number of 32 bit words comprising the Cipher key (128 bit standard is 4)
        * Nr -> Number of rounds, which is a function of Nk and Nb (128 bit standard is 10)
        """
        self.blocksize = blocksize

        if self.blocksize == 128:
            self.Nk, self.Nb, self.Nr = 4, 4, 10
        elif self.blocksize == 192:
            self.Nk, self.Nb, self.Nr = 6, 4, 12
        elif self.blocksize == 256:
            self.Nk, self.Nb, self.Nr = 8, 4, 14
    
    def encrypt(self, plaintext, key) -> str:
        #? Cast input to str and checks key's length
        assert len(key) in (16, 24, 32, 48, 64), "Warning: Invalid key length."

        key = str(key) if type(key) == int else key 
        plaintext = str(plaintext) if type(plaintext) == int else plaintext 

        #? First round
        blocks = self._divideIntoBlocks(plaintext)
        #? Key Expansion        
        roundKeys = self._getRoundKeys(key) 
        
        #? Intermediate rounds
        for block in blocks:    
            self._addRoundKey(roundKeys[0], block)    

            for each in range(1, self.Nr):
                self._subBytes(block)
                self._shiftRows(block)
                self._mixColumns(block)
                self._addRoundKey(roundKeys[each], block)

        #? Last round            
        self._subBytes(block)
        self._shiftRows(block)
        self._addRoundKey(roundKeys[self.Nr], block) 

        ciphertext = self._Reassemble(blocks)
        return ciphertext
    
    def _divideIntoBlocks(self, plaintext) -> list:
        """ 
        * Function performs the division of the input text into blocks of 128bit (16 bytes)
        * This function operates on three cases; Case 1: PLaintext in hex value Case 2: Plaintext in ascii characters
        """
        #? Divide plaintext into block of 4 by 4 bytes or 128 bits.  
        blocks, length = [], len(plaintext) 

        #? Case 1: For input that is already in hex string format
        if length == 32:
            temp = []
            for char in range(0, length, 2):
                temp.append(str("0x"+plaintext[char:char+2]))
            blocks.append(temp)

        #? Case 2: For ascii characters input
        else: 
            padding = 16 - length if length < 16 else length % 16

            #? Case 2: Input string that need padding
            if length < 16:
                #? ZeroLength Method
                plaintext += "0" * padding 

            temp = []
            for char in plaintext:
                temp.append(hex(ord(char))) #? Hexdecimals
            blocks.append(temp)
        return blocks
    
    def _getRoundKeys(self, key) -> list:
        """
        * Functions performs key whitening/ key schedule.The key schedule takes the original 
        * input key (of length 128, 192 or 256 bit) and derives the subkeys used in AES.
        * The number of subkeys is equal to the number rounds plus one, due to the key 
        * needed for key whitening in the first key addition layer. Nr + 1 = 11 subkeys
        """
        #?  An array of 4 bytes.
        word = 4 *[(self.Nr-1)] 

        #? Get key length
        keyLength = len(key)
    
        #? Divide key of hex string  into four words of 4 bytes length
        if keyLength in (32, 48, 64): 
            temp = [str("0x"+key[char:char+2]) for char in range(0, keyLength, 2)]
            word = [temp[char:char+4] for char in range(0, len(temp), 4)]
            del temp
        
        #? Divide key of ascii characters into four words of 4 bytes length and cast into hex string consequently
        else:    
            temp = None
            i = 0
            while i < self.Nk:
                #? First subkey division. Comprising of four words of hexdecimal string
                word[i] = [hex(ord(key[4*i])), hex(ord(key[4*i+1])), \
                            hex(ord(key[4*i+2])), hex(ord(key[4*i+3]))]
                i += 1   
        i = self.Nk

        #? Start key expansion loop
        while i < self.Nb * (self.Nr+1):
            temp = list(word[i-1])

            if i % self.Nk == 0:
                temp = self._rCon(self._subWord(self._rotWord(temp)), self._RCON[i//self.Nk])

            elif self.Nk > 6 and i % self.Nk == 4:
                temp = self._subWord(temp)

            word.append(self._aXorB(word[i-self.Nk], temp))
            i +=1
        
        #? Reassemble Word to keys
        word = self._reassembleWord(word)
        return word

    def _reassembleWord(self, word):
        """
        * Function takes word array and returns 16 bytes keys
        """
        temp, temp2 = [], []
        for each in range(len(word)):
            temp2.extend(word[each])
            if len(temp2) == 16:
                temp.append(temp2)
                temp2 = []
        word = temp[0:]
        del temp, temp2
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

    def _lookUpHex(self, hexString, inv=False) -> str:
        """
        * Function maps given hex string to its substitute value on S-Box and then returns it hex string value
        """
        if inv: #? SBox lookup for Inverse cipher
            hexString = hex(self._invSBox[int("0x"+hexString[0], 16)][int("0x"+hexString[1], 16)])
        else: #? SBox lookup for forward encryption   
            hexString = hex(self._sBox[int("0x"+hexString[0], 16)][int("0x"+hexString[1], 16)])
        
        return self._patchHex(hexString) if len(hexString) != 4 else hexString

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
            result = hex(int(v, 16) ^ int(key[k], 16))
            block[k] = self._patchHex(result) if len(result) != 4 else result
        return block

    def _subBytes(self, block) -> list:
        """
        * Functions takes an array of bytes then perform substitution: each byte in the block is replaced by 
        * the corresponding element from the fixed table (S-box).

        """
        return self._subWord(block)

    def _shiftRows(self, block) -> list:
        """
        * Function cyclically shifts the bytes in each row of the block by r bytes to the right, depending on the row number.
        """
        temp = [
            block[0], block[5], block[10], block[15], 
            block[4], block[9], block[14], block[3],
            block[8], block[13], block[2], block[7],
            block[12], block[1], block[6], block[11]
        ]        
        return self.__getBlocks(block, temp)
    
    def _mixColumnsAdd(self, subarray):
        """
        * Function takes a subarray of hex values, performs GF(2^m) addition then return a result value
        """
        return hex(int(subarray[0], 16) ^ int(subarray[1], 16) ^ int(subarray[2], 16) ^ int(subarray[3], 16))

    def _mixColumnsMult(self, bytes1, const, fixedPoly=0x1b):
        """
        * Function takes two bytes (bytes1 & const), and a fixed polynomial a(x) or a^-1(x) performs Galois Field Multiplication, then return a result value
        """
        # GF(2^m) mod p(x) -> Multiplication is done between two coefficients (byte1 & byte2) Overflow is modularated using byte1
        result = hex(int(bytes1, 16) * 2) if const > 0x01 else hex(int(bytes1, 16) * const)
        if len(result) > 4: # Overflow reduction using fixed polynomial 0x1b/a(x)
            result = hex(int(result, 16) ^ fixedPoly)
            if const == 0x03:
                result = hex(int(result, 16) ^ int(bytes1, 16))
            return result[:2] + result[3:] # Dropping overflow

        if len(result) < 4:
            result = self._patchHex(result)

        # Mulitiplication with 0x03 is always mod self
        if len(result) == 4 and const > 0x02:
                result = hex(int(result, 16) ^ int(bytes1, 16))
        return result
    
    def _mixColumns(self, block) -> list:
        """
        * Function consists of multiplying each column of the block with a constant matrix as follows:
        """
        #? Input 4 bytes i.e newly formed after shiftRow 0, 1, 2, 3
        const = [
            0x02, 0x03, 0x01, 0x01,
            0x01, 0x02, 0x03, 0x01,
            0x01, 0x01, 0x02, 0x03, 
            0x03, 0x01, 0x01, 0x02
        ]
        c = 0
        mixed = []
        for each in range(4, len(const)+1, 4):
            start = to = None
            for x in range(each-4, each):
                for _ in range(each, each+1):
                    start, to = each-4, each
                if x % 4 == 0:
                    c = 0
                mixed.append(self._mixColumnsAdd([self._mixColumnsMult(x, y) for x, y in zip(block[start:to], const[c:c+4])]))
                c +=4
        return self.__getBlocks(block, mixed)

    def __getBlocks(self, block, temp):
        """ Function copies the given array of bytes into the given block"""
        for each in range(len(temp)):
            block[each] =  self._patchHex(temp[each]) if len(temp[each]) != 4 else temp[each]
        del temp
        return block

    def _Reassemble(self, block) -> str:
        """ 
        * Function performs the ciphertext concatenation from blocks of 128bit (16 bytes)
        """
        ciphertext = ""
        for each in block:
            for char in each:
                ciphertext += "".join(char.split('0x'))
        return ciphertext

    def decrypt(self, state, key):
        """
        * Function start the reverse encryption process.
        """
        #? Starts with Final round of encryption
        state = self._divideIntoBlocks(state)[0]
        roundKeys = self._getRoundKeys(key)   

        self._addRoundKey(roundKeys[self.Nr], state) #? For 128-bit key 
        self._invShiftRows(state)
        self._invSubBytes(state)

        # #? Intermediate rounds
        for each in range(self.Nr-1, 0, -1):
            self._addRoundKey(roundKeys[each], state)
            self._invMixColumns(state)
            self._invShiftRows(state)
            self._invSubBytes(state)

        #? Finishes with First round of encryption
        self._addRoundKey(roundKeys[0], state)  
        
        plaintext = self._Reassemble([state])   
        # self.__hexToAscii(state)
        print(plaintext)
        return plaintext
    
    def __hexToAscii(self, hexString) -> None:
        """
        * Function convert hex string to ascii characters
        """
        plaintext = ""
        for each in hexString:
            plaintext += chr(int(each, 16))
        print(plaintext.strip("0"))

    def _invSubBytes(self, state):
        """
        * Functions substitute bytes for ciphertext using invSBox, then returns new state
        """
        for s in range(len(state)):
            state[s] = self._lookUpHex(state[s].split("0x")[1], True)
        return state

    def _invShiftRows(self, state):
        """
        * Function cyclically shifts the bytes in each row of the block by r bytes to the left, depending on the row number.
        """
        temp = [
            state[0], state[13], state[10], state[7], 
            state[4], state[1], state[14], state[11],
            state[8], state[5], state[2], state[15],
            state[12], state[9], state[6], state[3]
        ]
        return self.__getBlocks(state, temp)

    def _invMixColumns(self, state):
        """
        * Function
        """ 
        const = [
            0x0e, 0x0b, 0x0d, 0x09,
            0x09, 0x0e, 0x0b, 0x0d,
            0x0d, 0x09, 0x0e, 0x0b, 
            0x0b, 0x0d, 0x09, 0x0e
        ]
        c = 0
        mixed = []
        for each in range(4, len(const)+1, 4):
            start = to = None
            for x in range(each-4, each):
                for _ in range(each, each+1):
                    start, to = each-4, each
                if x % 4 == 0:
                    c = 0
                temp = self._mixColumnsAdd([hex(self.__galoisMult(x, y)) for x, y in zip(state[start:to], const[c:c+4])])
                mixed.append(self._patchHex(temp) if len(temp) < 4 else temp )
                c +=4
        return self.__getBlocks(state, mixed)

    def __galoisMult(self, a, b):
        """
        * Functions performs GF(2^8) Multiplication with irreducible polynomial 0x1b
        """
        p, a = 0, int(a, 16)
        hiBitSet = 0
        for i in range(8):
            if b & 1 == 1:
                p ^= a
            hiBitSet = a & 0x80
            a <<= 1
            if hiBitSet == 0x80:
                a ^= 0x1b
            b >>= 1
        return p % 256

    #? Substitution Table
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

    #? Round Coefficients
    _RCON = [
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
        0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
        0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
        0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
        0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
        0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
        0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
        0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
        0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
    ]

    #? Inverse Substitution Table
    _invSBox = [
        [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
        [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
        [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
        [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
        [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
        [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
        [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
        [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
        [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
        [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
        [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
        [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
        [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
        [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
        [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
        [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
    ]
