#ifndef GCM_H
#define GCM_H
#include "utils.h"

SubBlock AESEncryptionGCM(Block *block, const char *initial_counter, const char *increment, const char *auth_data, const unsigned char *expanded_key, const int Nr);
SubBlock calculateTag(Block *CipherBlock, const char *initial_counter, const char *auth_data, const unsigned char *expanded_key, const int Nr);
char *concatenate_sizes(const char *auth_data, const int cipher_size);
void AESDecryptionGCM(Block *block, const char *initial_counter, const char *increment, const char *auth_data, const unsigned char *expanded_key, const int Nr, SubBlock *TAG_gaved);

#endif /* GCM_H */