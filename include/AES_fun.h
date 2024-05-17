#ifndef AES_H
#define AES_H
#include "utils.h"
#define SUB_BLOCK_SIZE 16

void KeyExpansion(const char *key, const int key_size, unsigned char *expanded_key, int Nr);

void SubBytes(SubBlock *subblock);
void SubBytesBlock(Block *block);

void InvSubBytes(SubBlock *subblock);
void InvSubBytesBlock(Block *block);

void ShiftRows(SubBlock *subblock);
void ShiftRowsBlock(Block *block);

void InvShiftRows(SubBlock *subblock);
void InvShiftRowsBlock(Block *block);

void MixColumns(SubBlock *subblock);
void MixColumnsBlock(Block *block);

void InvMixColumns(SubBlock *subblock);
void InvMixColumnsBlock(Block *block);

void AESEncryption(SubBlock *subblock, const unsigned char *expanded_key, const int Nr);
void AESDecryption(SubBlock *subblock, const unsigned char *expanded_key, const int Nr);

void test_performance(SubBlock *subblock, const unsigned char *expanded_key);

#endif /* AES_H */