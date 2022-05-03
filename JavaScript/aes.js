class AES {
    //! This is for practice only
    
    constructor(blockSize=128) {
        this.blockSize = blockSize
    }

    encrypt(plaintext, key){}

    decrypt(ciphertext, key){}

    #divideIntoBlocks(plaintext) {}

    #getRoundKeys(key) {}

    #subWord(word) {}

    #addRoundKey(key, block) {}

    #subBytes(block) {}

    #shiftRows(block) {}

    #mixColumns(block) {}

    #Reassemble(block) {}

    #invCipher() {}

    #invSubBytes(state) {}

    #invShiftRows(state) {}

    #invMixColumns(state) {}
}

export default AES