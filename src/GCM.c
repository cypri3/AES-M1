#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include "utils.h"
#include "GCM.h"
#include "AES_fun.h"

/**
 * Function to perform AES encryption in Galois/Counter Mode (GCM).
 *
 * @param block The block to be encrypted.
 * @param initial_counter The initial value of the counter in hexadecimal format.
 * @param increment The value by which the counter is incremented in hexadecimal format.
 * @param auth_data Optional additional authentication data in hexadecimal format.
 * @param expanded_key The expanded encryption key generated using KeyExpansion function.
 * @param Nr The number of rounds in AES encryption (10, 12, or 14).
 * @return The authenticated encryption tag obtained after AES encryption in GCM mode.
 */
SubBlock AESEncryptionGCM(Block *block, const char *initial_counter, const char *increment, const char *auth_data, const unsigned char *expanded_key, const int Nr)
{
    // Create and initialize the counter subblock
    SubBlock *counter = create_subblock();
    if (!set_subblock_with_hex(counter, initial_counter))
    {
        printf("Failed to set subblock data.\n");
    }

    // Perform AES encryption on the counter
    AESEncryption(counter, expanded_key, Nr);

    // Create and initialize the initial work subblock
    SubBlock *initial_work = create_subblock();
    subblock_copy(counter, initial_work);

    // Create and initialize the increment subblock
    SubBlock *increment_subblock = create_subblock();
    if (!set_subblock_with_hex(increment_subblock, increment))
    {
        printf("Failed to set subblock data.\n");
    }

    // Create and initialize the work subblock
    SubBlock *work = create_subblock();

    // Iterate over each subblock in the block
    for (int i = 0; i < block->size; i++)
    {
        // Update the counter by XORing it with the increment subblock
        add_subblock_subblock(increment_subblock, counter);
        subblock_copy(counter, work);

        // Perform AES encryption on the work subblock
        AESEncryption(work, expanded_key, Nr);

        // XOR the encrypted work subblock with the current block subblock
        xor_subblock_subblock(work, &(block->sub_blocks[i]));
    }

    // Free allocated memory for subblocks
    free_subblock(counter);
    free_subblock(initial_work);
    free_subblock(increment_subblock);
    free_subblock(work);

    // Return the resulting authenticated encryption tag (Hwork)
    return calculateTag(block, initial_counter, auth_data, expanded_key, Nr);
}

/**
 * Calculates an authentication tag for a given cipher block using AES encryption.
 *
 * @param CipherBlock The block containing the cipher data.
 * @param initial_counter The initial value of the counter in hexadecimal format.
 * @param auth_data Optional additional authentication data in hexadecimal format.
 * @param expanded_key The expanded encryption key generated using KeyExpansion function.
 * @param Nr The number of rounds in AES encryption (10, 12, or 14).
 * @return A SubBlock structure containing the calculated authentication tag.
 */
SubBlock calculateTag(Block *CipherBlock, const char *initial_counter, const char *auth_data, const unsigned char *expanded_key, const int Nr)
{
    // Create and initialize the counter subblock
    SubBlock *counter = create_subblock();
    if (!set_subblock_with_hex(counter, initial_counter))
    {
        printf("Failed to set subblock data.\n");
    }

    // Perform AES encryption on the counter
    AESEncryption(counter, expanded_key, Nr);

    // Create and initialize the H subblock with zero data
    SubBlock *H = create_subblock();
    for (int i = 0; i < SUB_BLOCK_SIZE; i++)
    {
        H->data[i] = 0;
    }
    AESEncryption(H, expanded_key, Nr);

    // Initialize and calculate TAG by multiplying H with auth_data
    SubBlock *TAG = create_subblock();
    if (!set_subblock_with_hex(TAG, auth_data))
    {
        printf("Failed to set subblock data.\n");
    }
    multiply_uint(TAG, H);
    // Iterate over each subblock in the block
    for (int i = 0; i < CipherBlock->size; i++)
    {
        // XOR the current block subblock with TAG
        xor_subblock_subblock(&(CipherBlock->sub_blocks[i]), TAG);

        // Multiply TAG with H
        multiply_uint(TAG, H);
    }
    // Multiply TAG with H one more time
    multiply_uint(TAG, H);

    char *concatenated_data = concatenate_sizes(auth_data, CipherBlock->size);
    if (concatenated_data == NULL)
    {
        printf("Memory allocation failed in concatenate_sizes.\n");

        // Clean up allocated memory
        free_subblock(counter);
        free_subblock(H);
        return *TAG;
    }

    SubBlock *lenAlenC = create_subblock();
    if (!set_subblock_with_hex(lenAlenC, concatenated_data))
    {
        printf("Failed to set subblock data.\n");
    }

    xor_subblock_subblock(lenAlenC, TAG);

    // Free allocated memory for subblocks
    free_subblock(counter);
    free_subblock(H);
    free_subblock(lenAlenC);
    free(concatenated_data);

    // Return the resulting authenticated encryption tag
    return *TAG;
}

/**
 * Concatenates the effective hexadecimal length of auth_data and the number of cipher subblocks.
 *
 * @param auth_data A pointer to a character array containing hexadecimal data.
 * @param cipher_size An integer representing the number of cipher subblocks.
 * @return A pointer to a dynamically allocated string containing the concatenated hexadecimal values,
 *         which must be freed by the caller.
 */
char *concatenate_sizes(const char *auth_data, const int cipher_size)
{
    // Allocate memory for concatenated data, which should have a fixed size of 32 characters + null terminator
    char *concatenated_data = malloc(33);
    if (concatenated_data == NULL)
    {
        printf("Memory allocation failed.\n");
        return NULL;
    }

    // Initialize the memory to zeros
    memset(concatenated_data, '0', 32);

    // Calculate the effective length of the meaningful hexadecimal part of auth_data
    int i = 0;
    while (i < 32 && auth_data[i] == '0')
    {
        i += 1; // Skip characters one by one
    }
    int effective_auth_data_length = (i == 32) ? 0 : 32 - i; // If all zeros, consider length 0 else actual length without leading zeros

    // Convert effective length of auth_data to hexadecimal, represented as 16 hex digits
    char auth_data_lengths[17]; // Enough space for 16-character hex number and null terminator
    snprintf(auth_data_lengths, sizeof(auth_data_lengths), "%016X", effective_auth_data_length);

    // Convert cipher_size to hexadecimal, represented as 16 hex digits
    char cipher_size_lengths[17]; // Enough space for 16-character hex number and null terminator
    snprintf(cipher_size_lengths, sizeof(cipher_size_lengths), "%016X", cipher_size);

    // Place the formatted lengths into the concatenated data
    memcpy(concatenated_data, auth_data_lengths, 16);        // Copy the formatted auth_data length to the first half
    memcpy(concatenated_data + 16, cipher_size_lengths, 16); // Copy the formatted cipher size length to the second half

    concatenated_data[32] = '\0'; // Ensure null termination

    return concatenated_data;
}

/**
 * Function to perform AES encryption in Galois/Counter Mode (GCM).
 *
 * @param block The block to be encrypted.
 * @param key The encryption key in hexadecimal format.
 * @param key_size The size of the encryption key (128, 192, or 256 bits).
 * @param initial_counter The initial value of the counter in hexadecimal format.
 * @param increment The value by which the counter is incremented in hexadecimal format.
 * @param auth_data Optional additional authentication data in hexadecimal format.
 * @param expanded_key The expanded encryption key generated using KeyExpansion function.
 * @param Nr The number of rounds in AES encryption (10, 12, or 14).
 * @param TAG The authenticated encryption tag obtained after AES encryption in GCM mode.
 * @return True if the tag is valid else false.
 */
void AESDecryptionGCM(Block *block, const char *initial_counter, const char *increment, const char *auth_data, const unsigned char *expanded_key, const int Nr, SubBlock *TAG_gaved)
{
    SubBlock *TAG_subblock = create_subblock();
    *TAG_subblock = calculateTag(block, initial_counter, auth_data, expanded_key, Nr);

    xor_subblock_subblock(TAG_gaved, TAG_subblock);
    for (int i = 0; i < SUB_BLOCK_SIZE; i++)
    {
        if (TAG_subblock->data[i] != 0)
        {
            printf("Warning: Provided authentication tag does not match the calculated tag or no tag was provided.\n");
            i = SUB_BLOCK_SIZE;
        }
    }
    if (verbose)
    {
        printf("Provided authentication tag match the calculated tag.\n");
    }
    free_subblock(TAG_subblock);

    // Create and initialize the counter subblock
    SubBlock *counter = create_subblock();
    if (!set_subblock_with_hex(counter, initial_counter))
    {
        printf("Failed to set subblock data.\n");
    }

    // Perform AES encryption on the counter
    AESEncryption(counter, expanded_key, Nr);

    // Create and initialize the initial work subblock
    SubBlock *initial_work = create_subblock();
    subblock_copy(counter, initial_work);

    // Create and initialize the increment subblock
    SubBlock *increment_subblock = create_subblock();
    if (!set_subblock_with_hex(increment_subblock, increment))
    {
        printf("Failed to set subblock data.\n");
    }

    // Create and initialize the work subblock
    SubBlock *work = create_subblock();

    // Iterate over each subblock in the block
    for (int i = 0; i < block->size; i++)
    {
        // Update the counter by XORing it with the increment subblock
        add_subblock_subblock(increment_subblock, counter);
        subblock_copy(counter, work);

        // Perform AES encryption on the work subblock
        AESEncryption(work, expanded_key, Nr);

        // XOR the encrypted work subblock with the current block subblock
        xor_subblock_subblock(work, &(block->sub_blocks[i]));
    }

    // Free allocated memory for subblocks
    free_subblock(counter);
    free_subblock(initial_work);
    free_subblock(increment_subblock);
    free_subblock(work);
}