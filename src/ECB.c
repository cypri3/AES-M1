#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include "utils.h"
#include "AES_fun.h"

/**
 * Function to perform AES encryption in Electronic Codebook (ECB) mode.
 *
 * All constants are left as external calculations. Therefore, the expanded key can be kept for encryption and decryption without recalculating.
 *
 * @param block The block to be encrypted.
 * @param expanded_key The expanded encryption key generated using KeyExpansion function.
 * @param Nr The number of rounds in AES encryption (10, 12, or 14).
 */
void AESEncryptionECB(Block *block, const unsigned char *expanded_key, const int Nr)
{
    unsigned char temp_key[SUB_BLOCK_SIZE];
    // Apply XOR operation with the base key
    memcpy(temp_key, &(expanded_key[0]), SUB_BLOCK_SIZE); // TODO suppmier cette étape pour gagner un peu de temps

    xor_blocks_unsigned(block, temp_key);

    // Iterate over each round of AES encryption
    for (int round = 1; round < Nr; round++)
    {
        // Apply SubBytes
        SubBytesBlock(block);

        // Apply ShiftRows
        ShiftRowsBlock(block);

        // Apply MixColumns
        MixColumnsBlock(block);

        // Apply XOR operation with the round key
        memcpy(temp_key, &(expanded_key[(round)*SUB_BLOCK_SIZE]), SUB_BLOCK_SIZE);
        xor_blocks_unsigned(block, temp_key);
    }

    // For the last round, apply SubBytes, ShiftRows, and XOR operations with the round key
    // Apply SubBytes
    SubBytesBlock(block);

    // Apply ShiftRows
    ShiftRowsBlock(block);

    // Apply XOR operation with the last round key
    memcpy(temp_key, &(expanded_key[(Nr)*SUB_BLOCK_SIZE]), SUB_BLOCK_SIZE);
    xor_blocks_unsigned(block, temp_key);
}

/**
 * Function to perform AES decryption in Electronic Codebook (ECB) mode.
 *
 * All constants are left as external calculations. Therefore, the expanded key can be kept for encryption and decryption without recalculating.
 *
 * @param block The block to be decrypted.
 * @param expanded_key The expanded decryption key generated using KeyExpansion function.
 * @param Nr The number of rounds in AES decryption (10, 12, or 14).
 */
void AESDecryptionECB(Block *block, const unsigned char *expanded_key, const int Nr)
{
    unsigned char temp_key[SUB_BLOCK_SIZE];

    // Apply XOR with the Nr round key
    memcpy(temp_key, &(expanded_key[(Nr)*SUB_BLOCK_SIZE]), SUB_BLOCK_SIZE);
    xor_blocks_unsigned(block, temp_key);

    // Apply InvShiftRows
    InvShiftRowsBlock(block);

    // Apply InvSubBytes
    InvSubBytesBlock(block);

    // Apply XOR with the base key
    memcpy(temp_key, &(expanded_key[(Nr - 1) * SUB_BLOCK_SIZE]), SUB_BLOCK_SIZE);
    xor_blocks_unsigned(block, temp_key);

    // For all rounds from Nr - 2 to 0
    for (int round = Nr - 2; round > -1; round--)
    {
        // Apply InvMixColumns
        InvMixColumnsBlock(block);

        // Apply InvShiftRows
        InvShiftRowsBlock(block);

        // Apply InvSubBytes
        InvSubBytesBlock(block);

        // Apply XOR with the round key i
        memcpy(temp_key, &(expanded_key[(round)*SUB_BLOCK_SIZE]), SUB_BLOCK_SIZE);
        xor_blocks_unsigned(block, temp_key);
    }
}
