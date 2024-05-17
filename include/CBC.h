#ifndef CBC_H
#define CBC_H
#include "utils.h"

void AESEncryptionCBC(Block *block, const char *IV, const unsigned char *expanded_key, const int Nr);
void AESDecryptionCBC(Block *block, const char *IV, const unsigned char *expanded_key, const int Nr);

#endif /* CBC_H */