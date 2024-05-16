//
// Created by usagi on 5/15/2024.
//

#ifndef AESCYPHER_AESCYPHER_H
#define AESCYPHER_AESCYPHER_H


class AESCypher {
private:
    unsigned int m_rgu32State[16]{};

    // encryption methods
    void AddRoundKey(const unsigned int* rgu32Key);
    void SubBytes();
    void ShiftRows();
    void MixColumns();

    // decryption methods
    void SubRoundKey(const unsigned  int* rgu32Key);
    void InverseMixColumns();
    void InverseShiftRows();
    void InverseSubBytes();

public:
    unsigned int* Encrypt(const unsigned char* rgcMessage, const unsigned int rgcKey[176]);
    unsigned char* Decrypt(const unsigned char* rgu32Encrypted, const unsigned int rgcKey[176]);
};


#endif //AESCYPHER_AESCYPHER_H
