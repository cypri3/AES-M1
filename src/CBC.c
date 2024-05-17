#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include "utils.h"
#include "CBC.h"
#include "AES_fun.h"

/**
 * Function to perform AES encryption in Cipher Block Chaining (CBC) mode.
 *
 * @param block The block to be encrypted.
 * @param IV The initialization vector (IV) in hexadecimal format.
 * @param expanded_key The expanded encryption key generated using KeyExpansion function.
 * @param Nr The number of rounds in AES encryption (10, 12, or 14).
 */
void AESEncryptionCBC(Block *block, const char *IV, const unsigned char *expanded_key, const int Nr)
{
    // Create and initialize the IV subblock
    SubBlock *IV_subblock = create_subblock();
    if (!set_subblock_with_hex(IV_subblock, IV))
    {
        printf("Failed to set subblock data.\n");
    }

    // XOR the IV with the first block and encrypt it
    xor_subblock_subblock(IV_subblock, &(block->sub_blocks[0]));
    AESEncryption(&(block->sub_blocks[0]), expanded_key, Nr);

    // Iterate over each subsequent block in the block chain
    for (int i = 1; i < block->size; i++)
    {
        // XOR the previous block's ciphertext with the current block and encrypt it
        xor_subblock_subblock(&(block->sub_blocks[i - 1]), &(block->sub_blocks[i]));
        AESEncryption(&(block->sub_blocks[i]), expanded_key, Nr);
    }

    // Free allocated memory for the IV subblock
    free_subblock(IV_subblock);
}

/**
 * Function to perform AES decryption in Cipher Block Chaining (CBC) mode.
 *
 * @param block The block to be decrypted.
 * @param IV The initialization vector (IV) in hexadecimal format.
 * @param expanded_key The expanded encryption key generated using KeyExpansion function.
 * @param Nr The number of rounds in AES encryption (10, 12, or 14).
 */
void AESDecryptionCBC(Block *block, const char *IV, const unsigned char *expanded_key, const int Nr)
{
    // Decrypt each block in reverse order
    for (int i = block->size - 1; i > 0; i--)
    {
        // Decrypt the current block
        AESDecryption(&(block->sub_blocks[i]), expanded_key, Nr);

        // XOR the decrypted block with the previous block's ciphertext
        xor_subblock_subblock(&(block->sub_blocks[i - 1]), &(block->sub_blocks[i]));
    }

    // Create and initialize the IV subblock
    SubBlock *IV_subblock = create_subblock();
    if (!set_subblock_with_hex(IV_subblock, IV))
    {
        printf("Failed to set subblock data.\n");
    }

    // Decrypt the first block
    AESDecryption(&(block->sub_blocks[0]), expanded_key, Nr);

    // XOR the decrypted first block with the IV
    xor_subblock_subblock(IV_subblock, &(block->sub_blocks[0]));

    // Free allocated memory for the IV subblock
    free_subblock(IV_subblock);
}