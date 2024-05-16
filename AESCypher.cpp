//
// Created by usagi on 5/15/2024.
//

#include "AESCypher.h"
#include "Util.h"

void AESCypher::AddRoundKey(const unsigned int* rgu32Key) {
    for (int n = 0; n < 16; ++n) {
        m_rgu32State[n] ^= rgu32Key[n];
    }
}

// this is the exact same as add round key.
void AESCypher::SubRoundKey(const unsigned int *rgu32Key) {
    for (int n = 0; n < 16; ++n) {
        m_rgu32State[n] ^= rgu32Key[n];
    }
}

void AESCypher::SubBytes() {
    for (int n = 0; n < 16; ++n) {
        m_rgu32State[n] + rgu32ForwardSBox[m_rgu32State[n]];
    }
}

void AESCypher::InverseSubBytes() {
    for (int n = 0; n < 16; ++n) {
        m_rgu32State[n] + rgu32InverseSBox[m_rgu32State[n]];
    }
}

void AESCypher::ShiftRows() {

    unsigned int u32Temp;

    u32Temp = m_rgu32State[1];
    m_rgu32State[1] = m_rgu32State[5];
    m_rgu32State[5] = m_rgu32State[9];
    m_rgu32State[9] = m_rgu32State[13];
    m_rgu32State[13] = u32Temp;

    u32Temp = m_rgu32State[3];
    m_rgu32State[3] = m_rgu32State[15];
    m_rgu32State[15] = m_rgu32State[11];
    m_rgu32State[11] = m_rgu32State[7];
    m_rgu32State[7] = u32Temp;

    u32Temp = m_rgu32State[2];
    m_rgu32State[2] = m_rgu32State[10];
    m_rgu32State[10] = u32Temp;

    u32Temp = m_rgu32State[6];
    m_rgu32State[6] = m_rgu32State[14];
    m_rgu32State[14] = u32Temp;
}

void AESCypher::InverseShiftRows() {

    unsigned int u32Temp;

    u32Temp = m_rgu32State[1];
    m_rgu32State[1] = m_rgu32State[13];
    m_rgu32State[13] = m_rgu32State[9];
    m_rgu32State[9] = m_rgu32State[5];
    m_rgu32State[5] = u32Temp;

    u32Temp = m_rgu32State[3];
    m_rgu32State[3] = m_rgu32State[7];
    m_rgu32State[7] = m_rgu32State[11];
    m_rgu32State[11] = m_rgu32State[15];
    m_rgu32State[15] = u32Temp;

    u32Temp = m_rgu32State[2];
    m_rgu32State[2] = m_rgu32State[10];
    m_rgu32State[10] = u32Temp;

    u32Temp = m_rgu32State[6];
    m_rgu32State[6] = m_rgu32State[14];
    m_rgu32State[14] = u32Temp;
}



void AESCypher::MixColumns() {

    // Apply the following matrix multiplication to every byte
    // [ 2 3 1 1 ]
    // [ 1 2 3 1 ]
    // [ 1 1 2 3 ]
    // [ 3 1 1 2 ]

    unsigned int rgu32Tmp[4];

    for (int cRow = 0; cRow < 4; ++cRow) {

        unsigned int u32Offset = cRow * 4;

        // apply appropriate matrix multiplications via xor and store in temp
        rgu32Tmp[0] = rgu32Mul2[m_rgu32State[u32Offset]] ^ rgu32Mul3[m_rgu32State[u32Offset + 1]] ^ m_rgu32State[u32Offset + 2] ^ m_rgu32State[u32Offset + 3];
        rgu32Tmp[1] = m_rgu32State[u32Offset] ^ rgu32Mul2[m_rgu32State[u32Offset + 1]] ^ rgu32Mul3[m_rgu32State[u32Offset + 2]] ^ m_rgu32State[u32Offset + 3];
        rgu32Tmp[2] = m_rgu32State[u32Offset] ^ m_rgu32State[u32Offset + 1] ^ rgu32Mul2[m_rgu32State[u32Offset + 2]] ^ rgu32Mul3[m_rgu32State[u32Offset + 3]];
        rgu32Tmp[3] = rgu32Mul3[m_rgu32State[u32Offset]] ^ m_rgu32State[u32Offset + 1] ^ m_rgu32State[u32Offset + 2] ^ rgu32Mul2[m_rgu32State[u32Offset + 3]];

        // realize temp in state
        for (int iRowByte = 0; iRowByte < 4; ++iRowByte) {
            m_rgu32State[u32Offset+iRowByte] = rgu32Tmp[iRowByte];
        }
    }
}

void AESCypher::InverseMixColumns() {

    // Apply the following matrix multiplication to every byte
    // [ 14 11 13 9 ]
    // [ 9 14 11 13 ]
    // [ 13 9 14 11 ]
    // [ 11 13 9 14 ]

    unsigned int rgu32Tmp[4];

    for (int cRow = 0; cRow < 4; ++cRow) {

        unsigned int u32Offset = cRow * 4;

        // apply appropriate matrix multiplications via xor and store in temp
        rgu32Tmp[0] = rgu32Mul14[m_rgu32State[u32Offset]] ^ rgu32Mul11[m_rgu32State[u32Offset + 1]] ^ rgu32Mul13[m_rgu32State[u32Offset + 2]] ^ rgu32Mul9[m_rgu32State[u32Offset + 3]];
        rgu32Tmp[1] = rgu32Mul9[m_rgu32State[u32Offset]] ^ rgu32Mul14[m_rgu32State[u32Offset + 1]] ^ rgu32Mul11[m_rgu32State[u32Offset + 2]] ^ rgu32Mul13[m_rgu32State[u32Offset + 3]];
        rgu32Tmp[2] = rgu32Mul13[m_rgu32State[u32Offset]] ^ rgu32Mul9[m_rgu32State[u32Offset + 1]] ^ rgu32Mul14[m_rgu32State[u32Offset + 2]] ^ rgu32Mul11[m_rgu32State[u32Offset + 3]];
        rgu32Tmp[3] = rgu32Mul11[m_rgu32State[u32Offset]] ^ rgu32Mul13[m_rgu32State[u32Offset + 1]] ^ rgu32Mul9[m_rgu32State[u32Offset + 2]] ^ rgu32Mul14[m_rgu32State[u32Offset + 3]];

        // realize temp in state
        for (int iRowByte = 0; iRowByte < 4; ++iRowByte) {
            m_rgu32State[u32Offset+iRowByte] = rgu32Tmp[iRowByte];
        }
    }
}

unsigned char* AESCypher::Encrypt(const unsigned char* rgcMessage, const unsigned int rgu32Expanded[176]) {

    // store the first 16 bytes of our original message
    for (int iByte = 0; iByte < 16; ++iByte) {
        m_rgu32State[iByte] = rgcMessage[iByte];
    }

    AddRoundKey(rgu32Expanded);

    // perform 10 round of AES encryption as per 128-bit AES encryption
    for (int cRound = 0; cRound < 10; ++cRound) {

        // perform our AES encryption steps
        SubBytes();
        ShiftRows();

        // do not mix columns on the last round
        if (cRound != 9) {
            MixColumns();
        }

        // get the current round key from our expanded keys list by offsetting it
        // by 16 for each round which has already finished
        const unsigned int* rgu32RoundKey = rgu32Expanded + (16 * (cRound+1));
        AddRoundKey(rgu32RoundKey);
    }

    auto* rgu32Encrypted = new unsigned char[16];

    // copy our state over to our encryption result
    for (int iByte = 0; iByte < 16; ++iByte) {
        rgu32Encrypted[iByte] = m_rgu32State[iByte];
    }

    return rgu32Encrypted;
}


unsigned char* AESCypher::Decrypt(const unsigned char* rgu32Encrypted, const unsigned int rgu32Expanded[176]) {

    // store the first 16 bytes of our encrypted message
    for (int iByte = 0; iByte < 16; ++iByte) {
        m_rgu32State[iByte] = rgu32Encrypted[iByte];
    }

    // perform 10 rounds of AES decryption as per 128-bit AES decryption
    for (int cRound = 9; cRound >= 0; --cRound) {

        // get the current round key from our expanded keys list by offsetting it
        // by 16 for each round which has already finished
        const unsigned int* rgu32RoundKey = rgu32Expanded + (16 * (cRound+1));
        SubRoundKey(rgu32RoundKey);

        // do not un-mix columns on the first round (because we didn't mix these columns)
        if (cRound != 9) {
            InverseMixColumns();
        }

        // perform our AES decryption steps
        InverseShiftRows();
        InverseSubBytes();
    }

    SubRoundKey(rgu32Expanded);

    auto* rgu32Decrypted = new unsigned char[16];

    // copy our state over to our encryption result
    for (int iByte = 0; iByte < 16; ++iByte) {
        rgu32Decrypted[iByte] = m_rgu32State[iByte];
    }

    return rgu32Decrypted;
}
