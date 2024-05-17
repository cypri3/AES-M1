#ifndef CFB_H
#define CFB_H
#include "utils.h"

void AESEncryptionCFB(Block *block, const char *IV, const unsigned char *expanded_key, const int Nr);
void AESDecryptionCFB(Block *block, const char *IV, const unsigned char *expanded_key, const int Nr);

#endif /* CFB_H */