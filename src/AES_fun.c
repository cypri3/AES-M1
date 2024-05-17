#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "utils.h"

#define SUB_BLOCK_SIZE 16

// Definition of Rijndael S-box
unsigned char SBox[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16},
};

/**
 * Function to perform key expansion for AES-X.
 *
 * @param key The original key.
 * @param key_size The size of the original key in bits.
 * @param expanded_key Pointer to store the expanded key.
 * @param Nr The number of rounds for AES-X.
 */
void KeyExpansion(const char *key, const int key_size, unsigned char *expanded_key, int Nr)
{
    unsigned char Rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
    int keySize = key_size / 8; // Variable key_size / 8 here to avoid too many divisions by 8 in the rest of the function
    int i, j, k;
    unsigned char temp[4];

    // The first part of the expansion key is the original key
    for (i = 0; i < keySize; ++i)
    {

        char byte_string[3];                  // Store the byte in text format (e.g., "0A")
        strncpy(byte_string, &key[i * 2], 2); // Extract the hexadecimal byte
        byte_string[2] = '\0';                // Terminate the string

        unsigned int byte_value = (unsigned int)strtol(byte_string, NULL, SUB_BLOCK_SIZE); // Convert the hexadecimal byte to an integer
        expanded_key[i] = byte_value;
    }

    // Remaining key words of the key expansion
    for (i = keySize; i < (Nr + 1) * SUB_BLOCK_SIZE; i += 4)
    {
        for (j = 0; j < 4; ++j)
        {
            temp[j] = expanded_key[i - 4 + j];
        }
        if (i % keySize == 0)
        {
            // Perform RotWord() on temp
            unsigned char t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // Perform SubWord() on temp
            for (j = 0; j < 4; ++j)
            {
                temp[j] = SBox[temp[j] >> 4][temp[j] & 0x0F];
            }

            // XOR with Rcon
            temp[0] ^= Rcon[i / keySize];
        }
        else if (keySize > 24 && i % keySize == 16)
        {
            // Perform SubWord() on temp
            for (j = 0; j < 4; ++j)
            {
                temp[j] = SBox[temp[j] >> 4][temp[j] & 0x0F];
            }
        }

        // XOR with the previous key word
        for (k = 0; k < 4; ++k)
        {
            expanded_key[i + k] = expanded_key[i + k - keySize] ^ temp[k];
        }
    }
}

/**
 * Function to apply the SubBytes transformation.
 *
 * @param subblock A pointer to the sub-block to which the SubBytes transformation is applied.
 */
void SubBytes(SubBlock *subblock)
{
    for (int i = 0; i < SUB_BLOCK_SIZE; i++)
    {
        int row = (subblock->data[i] >> 4) & 0x0F; // Extracting the row // Masking to ensure only the lower 4 bits are considered (0x0F)
        int col = subblock->data[i] & 0x0F;        // Extracting the column
        subblock->data[i] = SBox[row][col];        // Replacing with the value from the S-box
    }
}

/**
 * Function to apply the SubBytes transformation on a block.
 *
 * @param block A pointer to the block to which the SubBytes transformation is applied.
 */
void SubBytesBlock(Block *block)
{
    for (int i = 0; i < block->size; i++)
    {
        SubBytes(&(block->sub_blocks[i]));
    }
}

/**
 * Function to apply the InvSubBytes transformation.
 *
 * @param subblock A pointer to the sub-block to which the InvSubBytes transformation is applied.
 */
void InvSubBytes(SubBlock *subblock)
{

    // Définition de la Rijndael Inverse S-box
    unsigned char inverse_s_box[16][16] = {
        {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
        {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
        {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
        {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
        {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
        {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
        {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
        {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
        {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
        {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
        {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
        {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
        {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
        {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
        {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
        {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d},
    };

    for (int i = 0; i < SUB_BLOCK_SIZE; i++)
    {
        int row = (subblock->data[i] >> 4) & 0x0F;   // Extract the row
        int col = subblock->data[i] & 0x0F;          // Extract the column
        subblock->data[i] = inverse_s_box[row][col]; // Replace by the inverse S-box value
    }
}

/**
 * Function to apply the InvSubBytes transformation on a block.
 *
 * @param block A pointer to the block to which the InvSubBytes transformation is applied.
 */
void InvSubBytesBlock(Block *block)
{
    for (int i = 0; i < block->size; i++)
    {
        InvSubBytes(&(block->sub_blocks[i]));
    }
}

/**
 * Function to perform the ShiftRows operation on a sub-block.
 *
 * @param subblock A pointer to the sub-block on which the ShiftRows operation is to be performed.
 */
void ShiftRows(SubBlock *subblock)
{
    // Shift the rows of the sub-block
    for (int i = 1; i < 4; i++)
    {
        // Number of shifts to perform for the current row
        int shift_amount = i;

        // Circular shifting of elements in the row
        for (int j = 0; j < shift_amount; j++)
        {
            unsigned int temp = subblock->data[i];
            for (int k = 0; k < 3; k++)
            {
                subblock->data[i + (k * 4)] = subblock->data[i + ((k + 1) * 4)];
            }
            subblock->data[i + 12] = temp;
        }
    }
}

/**
 * Function to perform the ShiftRows operation on a block.
 *
 * @param block A pointer to the block on which the ShiftRows operation is to be performed.
 */
void ShiftRowsBlock(Block *block)
{
    for (int i = 0; i < block->size; i++)
    {
        ShiftRows(&(block->sub_blocks[i]));
    }
}

/**
 * Function to perform the InvShiftRows operation on a sub-block.
 *
 * @param subblock A pointer to the sub-block on which the InvShiftRows operation is to be performed.
 */
void InvShiftRows(SubBlock *subblock)
{
    // Shift the rows of the sub-block
    for (int i = 1; i < 4; i++)
    {
        // Number of shifts to perform for the current row
        int shift_amount = i;

        // Circular shifting of elements in the row
        for (int j = 0; j < shift_amount; j++)
        {
            unsigned int temp = subblock->data[i + 12];
            for (int k = 2; k >= 0; k--)
            {
                subblock->data[i + ((k + 1) * 4)] = subblock->data[i + (k * 4)];
            }
            subblock->data[i] = temp;
        }
    }
}

/**
 * Function to perform the InvShiftRows operation on a block.
 *
 * @param block A pointer to the block on which the InvShiftRows operation is to be performed.
 */
void InvShiftRowsBlock(Block *block)
{
    for (int i = 0; i < block->size; i++)
    {
        InvShiftRows(&(block->sub_blocks[i]));
    }
}

/**
 * Function to apply the MixColumns operation on a sub-blocks.
 *
 * @param sub_block A pointer to the sub-blocks on which the MixColumns operation is to be applied.
 */
void MixColumns(SubBlock *sub_block)
{
    // MixColumns transformation matrix
    unsigned char mix_columns_matrix[4][4] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}};

    for (int s = 0; s < 16; s += 4)
    {
        // Create a temporary copy of the sub-block
        unsigned int temp_block[4]; // TODO Delet this optional step ?
        for (int j = 0; j < 4; j++)
        {
            temp_block[j] = sub_block->data[j + s];
        }

        // Apply the MixColumns transformation
        for (int j = 0; j < 4; j++)
        {
            unsigned char result = 0;
            for (int k = 0; k < 4; k++)
            {
                result ^= multiply(mix_columns_matrix[j][k], temp_block[k]);
            }
            sub_block->data[j + s] = result;
        }
    }
}

/**
 * Function to apply the MixColumns operation on a blocks.
 *
 * @param block A pointer to the blocks on which the MixColumns operation is to be applied.
 */
void MixColumnsBlock(Block *block)
{
    for (int i = 0; i < block->size; i++)
    {
        MixColumns(&(block->sub_blocks[i]));
    }
}

/**
 * Function to apply the InvMixColumns operation on a sub-blocks.
 *
 * @param sub_block A pointer to the sub-blocks on which the InvMixColumns operation is to be applied.
 */
void InvMixColumns(SubBlock *sub_block)
{
    // InvMixColumns transformation matrix
    unsigned char inv_mix_columns_matrix[4][4] = {
        {0x0E, 0x0B, 0x0D, 0x09},
        {0x09, 0x0E, 0x0B, 0x0D},
        {0x0D, 0x09, 0x0E, 0x0B},
        {0x0B, 0x0D, 0x09, 0x0E}};

    for (int s = 0; s < 16; s += 4)
    {
        // Create a temporary copy of the sub-block
        unsigned int temp_block[4];
        for (int j = 0; j < 4; j++)
        {
            temp_block[j] = sub_block->data[j + s];
        }

        // Apply the MixColumns transformation
        for (int j = 0; j < 4; j++)
        {
            unsigned char result = 0;
            for (int k = 0; k < 4; k++)
            {
                result ^= multiply(inv_mix_columns_matrix[j][k], temp_block[k]);
            }
            sub_block->data[j + s] = result;
        }
    }
}

/**
 * Function to apply the InvMixColumns operation on a blocks.
 *
 * @param block A pointer to the blocks on which the InvMixColumns operation is to be applied.
 */
void InvMixColumnsBlock(Block *block)
{
    for (int i = 0; i < block->size; i++)
    {
        InvMixColumns(&(block->sub_blocks[i]));
    }
}

/**
 * Function to perform AES encryption on a sub-block.
 *
 * @param subblock A pointer to the sub-block to be encrypted.
 * @param expanded_key An array containing the expanded key for encryption.
 * @param Nr The number of rounds for AES encryption.
 */
void AESEncryption(SubBlock *subblock, const unsigned char *expanded_key, const int Nr)
{
    // Apply XOR with the base key directly
    xor_subblock_unsigned(subblock, expanded_key);

    // For all rounds from 1 to Nr
    for (int round = 1; round < Nr; round++)
    {
        // Apply SubBytes
        SubBytes(subblock);

        // Apply ShiftRows
        ShiftRows(subblock);

        // Apply MixColumns
        MixColumns(subblock);

        // Apply XOR with the key of round directly from the expanded key array
        xor_subblock_unsigned(subblock, expanded_key + round * SUB_BLOCK_SIZE);
    }

    // For the last step, do the same but without MixColumns
    SubBytes(subblock);  // Apply SubBytes
    ShiftRows(subblock); // Apply ShiftRows

    // Apply XOR with the key of the last round directly from the expanded key array
    xor_subblock_unsigned(subblock, expanded_key + Nr * SUB_BLOCK_SIZE);
}

/**
 * Function to perform AES decryption on a sub-block.
 *
 * @param subblock A pointer to the sub-block to be decrypted.
 * @param expanded_key An array containing the expanded key for decryption.
 * @param Nr The number of rounds for AES decryption.
 */
void AESDecryption(SubBlock *subblock, const unsigned char *expanded_key, const int Nr)
{
    unsigned char temp_key[SUB_BLOCK_SIZE];

    // Apply XOR with the key of round Nr
    memcpy(temp_key, &(expanded_key[(Nr)*SUB_BLOCK_SIZE]), SUB_BLOCK_SIZE);
    xor_subblock_unsigned(subblock, temp_key);

    // Apply InvShiftRows
    InvShiftRows(subblock);

    // Apply InvSubBytes
    InvSubBytes(subblock);

    // Apply XOR with the base key
    memcpy(temp_key, &(expanded_key[(Nr - 1) * SUB_BLOCK_SIZE]), SUB_BLOCK_SIZE);
    xor_subblock_unsigned(subblock, temp_key);

    // For all rounds from 1 to Nr - 1
    for (int round = Nr - 2; round > -1; round--)
    {
        // Apply InvMixColumns
        InvMixColumns(subblock);

        // Apply InvShiftRows
        InvShiftRows(subblock);

        // Apply InvSubBytes
        InvSubBytes(subblock);

        // Apply XOR with the key of round i
        memcpy(temp_key, &(expanded_key[(round)*SUB_BLOCK_SIZE]), SUB_BLOCK_SIZE);
        xor_subblock_unsigned(subblock, temp_key);
    }
}

void test_performance(SubBlock *subblock, const unsigned char *expanded_key)
{
    clock_t start, end;
    double cpu_time_used;

    // Test SubBytes 8958000  times
    start = clock();
    for (int i = 0; i < 8958000; i++)
    {
        SubBytes(subblock);
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("SubBytes 8958000 x: %f seconds\n", cpu_time_used);

    // Test ShiftRows 8958000  times
    start = clock();
    for (int i = 0; i < 8958000; i++)
    {
        ShiftRows(subblock);
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("ShiftRows 8958000 x: %f seconds\n", cpu_time_used);

    // Test MixColumns 8958000  times
    start = clock();
    for (int i = 0; i < 8958000; i++)
    {
        MixColumns(subblock);
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("MixColumns 8958000 x: %f seconds\n", cpu_time_used);

    // Test xor_subblock_unsigned 8958000  times
    start = clock();
    for (int i = 0; i < 8958000; i++)
    {
        xor_subblock_unsigned(subblock, expanded_key + i % 10 * SUB_BLOCK_SIZE); // Example variation
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("xor_subblock_unsigned 8958000 x: %f seconds\n", cpu_time_used);
}