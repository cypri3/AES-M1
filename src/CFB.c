#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include "utils.h"
#include "CFB.h"
#include "AES_fun.h"

/**
 * Function to perform AES encryption in Cipher Feedback (CFB) mode.
 *
 * @param block The block to be encrypted.
 * @param IV The initialization vector (IV) in hexadecimal format.
 * @param expanded_key The expanded encryption key generated using KeyExpansion function.
 * @param Nr The number of rounds in AES encryption (10, 12, or 14).
 */
void AESEncryptionCFB(Block *block, const char *IV, const unsigned char *expanded_key, const int Nr)
{
    // Create a temporary work subblock
    SubBlock *work = create_subblock();

    // Create and initialize the IV subblock
    SubBlock *subblockIV = create_subblock();
    if (subblockIV != NULL)
    {
        if (!set_subblock_with_hex(subblockIV, IV))
        {
            printf("Failed to set subblock data.\n");
            // Free allocated memory in case of failure
            free(subblockIV->data);
            free(subblockIV);
        }
    }
    else
    {
        printf("Failed to create subblock.\n");
    }

    // Encrypt the IV using AES encryption with the expanded key
    AESEncryption(subblockIV, expanded_key, Nr);

    // XOR the first block with the encrypted IV
    xor_subblock_subblock(&(block->sub_blocks[0]), subblockIV);
    // Copy the encrypted IV to the work subblock
    subblock_copy(&(block->sub_blocks[0]), work);

    // Encrypt each subsequent block and update the work subblock
    for (int i = 1; i < block->size; i++)
    {
        // Encrypt the work subblock using AES encryption with the expanded key
        AESEncryption(work, expanded_key, Nr);
        // XOR the current block with the encrypted work subblock
        xor_subblock_subblock(&(block->sub_blocks[i]), work);
        // Copy the encrypted block to the work subblock for the next iteration
        subblock_copy(&(block->sub_blocks[i]), work);
    }

    // Free allocated memory for the temporary work subblock
    free_subblock(work);
    free_subblock(subblockIV);
}

/**
 * Function to perform AES decryption in Cipher Feedback (CFB) mode.
 *
 * @param block The block to be decrypted.
 * @param IV The initialization vector (IV) in hexadecimal format.
 * @param expanded_key The expanded encryption key generated using KeyExpansion function.
 * @param Nr The number of rounds in AES encryption (10, 12, or 14).
 */
void AESDecryptionCFB(Block *block, const char *IV, const unsigned char *expanded_key, const int Nr)
{
    // Create a temporary work subblock
    SubBlock *work = create_subblock();

    // Decrypt each block in reverse order
    for (int i = block->size - 1; i > 0; i--)
    {
        // Copy the previous ciphertext block to the work subblock
        subblock_copy(&(block->sub_blocks[i - 1]), work);
        // Apply AES encryption to the work subblock using the expanded key
        AESEncryption(work, expanded_key, Nr);
        // XOR the current ciphertext block with the encrypted work subblock to get plaintext
        xor_subblock_subblock(&(block->sub_blocks[i]), work);
    }

    // Initialize the work subblock with the IV
    if (!set_subblock_with_hex(work, IV))
    {
        printf("Failed to set subblock data.\n");
    }
    // Apply AES encryption to the IV using the expanded key
    AESEncryption(work, expanded_key, Nr);
    // XOR the first ciphertext block with the encrypted IV to get plaintext
    xor_subblock_subblock(&(block->sub_blocks[0]), work);

    // Free allocated memory for the temporary work subblock
    free_subblock(work);
}