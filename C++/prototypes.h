#include <string>

#ifndef PROTOTYPES_H
#define PROTOTYPES_H

class AES {
    //! This is for practice only

    public:
        int plaintext;
        int key;

        string plaintext;
        string key;

        int blockSize;

        AES() {};
        AES(int b, string p, string k) {};
        AES(int b, int p, int k) {};

        void encrypt() {};

        string decrypt(string ciphertext) {};

    protected:
        string *divideIntoBlocks() {};
        string *getRoundKeys() {};
        string *subWord() {};
        string *rotWord() {};
        string *addRoundKey() {};
        string *subBytes() {};
        string *shiftRows() {};
        string *mixColumns() {};
        string Reassemble() {};
        string invCipher() {};
        string *invSubBytes() {};
        string *invShiftRows() {};
        string *invMixColumns() {};
};
#endif