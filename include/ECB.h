#ifndef ECB_H
#define ECB_H
#include "utils.h"

void AESEncryptionECB(Block *block, const unsigned char *expanded_key, const int Nr);
void AESDecryptionECB(Block *block, const unsigned char *expanded_key, const int Nr);

#endif /* ECB_H */