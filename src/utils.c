#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <time.h>
#include "utils.h"
#include "multiplication_table.h"
#include <ctype.h> // Tests' librairies for keys

#define BLOCK_SIZE 128
#define SUB_BLOCK_SIZE 16

/**
 * This function checks if a key matches the following conditions :
 * - an hexadicimal key
 * - a 128, 192 or 256 bits key
 *
 * @param key The key to test.
 * @return 1 if the size is valid, 0 otherwise.
 */
int valid_key(const char *key)
{
    // Check if the key length is valid (32, 48, or 64 characters)
    size_t len = strlen(key);
    if (len != 32 && len != 48 && len != 64)
    {
        return 0;
    }

    // Check if all characters are valid (digits 0 to 9 and letters a to f)
    for (size_t i = 0; i < len; i++)
    {
        if (!isxdigit(key[i])) // Hexadecimal validation (0-9 A-F a-f)
        {
            return 0;
        }
    }

    return 1;
}

/**
 * Function to validate an initialization vector (IV) for AES encryption.
 *
 * This function checks if the provided IV is valid for AES encryption. The IV must be a hexadecimal string
 * of length 32 characters. It also verifies that all characters are valid hexadecimal digits (0-9, A-F, a-f).
 *
 * @param IV The initialization vector (IV) to be validated.
 * @return 1 if the IV is valid, 0 otherwise.
 */
int valid_IV(const char *IV)
{
    // Check if the key length is valid 32
    size_t len = strlen(IV);
    if (len != 32)
    {
        return 0;
    }

    // Check if all characters are valid (digits 0 to 9 and letters a to f)
    for (size_t i = 0; i < len; i++)
    {
        if (!isxdigit(IV[i])) // Hexadecimal validation (0-9 A-F a-f)
        {
            return 0;
        }
    }

    return 1;
}

/**
 * Validates and adjusts the authentication tag to ensure it matches the required length.
 *
 * @param auth_data The input authentication tag in hexadecimal format.
 * @return 1 if the authentication tag is valid, 0 otherwise.
 */
int valid_auth_data(char *auth_data)
{
    size_t len = strlen(auth_data);

    // Check if the length is greater than the allowed maximum and truncate if necessary
    if (len > 32)
    {
        auth_data[32] = '\0';
        len = 32;
    }

    // Check if the length is less than the minimum and pad with zeros if necessary
    if (len < 32)
    {
        char padded_auth_data[32 + 1];
        memset(padded_auth_data, '0', 32 - len);          // Fill the remaining space with zeros
        strcpy(padded_auth_data + (32 - len), auth_data); // Copy the original auth_data to the right
        strcpy(auth_data, padded_auth_data);              // Update the original auth_data with the padded version
    }

    // Verify that the auth_data contains only valid hexadecimal digits
    for (size_t i = 0; i < 32; i++)
    {
        if (!isxdigit(auth_data[i]))
        {
            return 0;
        }
    }

    return 1;
}

/**
 * This function generates a random key of the specified size in bits.
 *
 * @param key_size The size of the key in bits (128, 192, or 256).
 * @param key The buffer to store the generated key.
 */
void generate_random_key(int key_size, char *key)
{
    // Define the size in bytes
    int size_in_bytes = key_size / 8;

    // Generate a random key
    for (int i = 0; i < size_in_bytes; i++)
    {
        key[i] = rand() % 256; // Generate a random byte
    }
}

/**
 * This function reads the content of a file and returns it as a character array.
 *
 * @param filename The name of the file to be read.
 * @param file_size Pointer to a long integer where the size of the file will be stored.
 * @param as_hexadecimal If true, the file is read as hexadecimal and converted to binary.
 * @return A pointer to the character array containing the content of the file.
 */
char *read_file(const char *filename, long int *file_size, bool as_hexadecimal)
{
    FILE *file = fopen(filename, "rb");
    if (file == NULL)
    {
        fprintf(stderr, "Failed to open file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    // Determine the size of the file
    fseek(file, 0, SEEK_END);
    long int original_file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory to contain the file content
    char *file_content = (char *)malloc(original_file_size + 1); // +1 for the null terminator
    if (file_content == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    // Read the content of the file
    size_t bytes_read = fread(file_content, 1, original_file_size, file);
    if ((long int)bytes_read != original_file_size)
    {
        fprintf(stderr, "Failed to read file %s\n", filename);
        fclose(file);
        free(file_content);
        exit(EXIT_FAILURE);
    }

    // Add a null terminator
    file_content[original_file_size] = '\0';

    // Close the file
    fclose(file);

    if (as_hexadecimal)
    {
        // Determine the binary file size based on the number of hex pairs
        *file_size = original_file_size / 2;
        char *binary_content = (char *)malloc(*file_size);
        if (binary_content == NULL)
        {
            fprintf(stderr, "Memory allocation failed\n");
            free(file_content);
            exit(EXIT_FAILURE);
        }

        // Convert hex string to binary
        for (long int i = 0; i < *file_size; i++)
        {
            char hex_pair[3] = {file_content[2 * i], file_content[2 * i + 1], '\0'};
            binary_content[i] = (char)strtol(hex_pair, NULL, 16);
        }

        free(file_content);
        return binary_content;
    }
    else
    {
        *file_size = original_file_size;
        return file_content;
    }
}

/**
 * Function to create a new subblock.
 *
 * @return A pointer to the newly created subblock, or NULL if memory allocation fails.
 */
SubBlock *create_subblock()
{
    SubBlock *sub_blocks = malloc(sizeof(SubBlock));
    if (sub_blocks == NULL)
    {
        // Handle memory allocation error
        free(sub_blocks); // Free already allocated memory
        return NULL;
    }
    // Allocate memory for the data of each sub-block

    sub_blocks->data = malloc(SUB_BLOCK_SIZE * sizeof(unsigned int));
    if (sub_blocks->data == NULL)
    {
        // Handle memory allocation error
        // Free already allocated memory
        free(sub_blocks->data);
        free(sub_blocks);
        return NULL;
    }

    return sub_blocks;
}

/**
 * Function to create a new subblock.
 *
 * @return A pointer to the newly created subblock, or NULL if memory allocation fails.
 */
void free_subblock(SubBlock *subblock)
{
    free(subblock->data);
    free(subblock);
}

/**
 * Function to set the data of a subblock from a hexadecimal key.
 *
 * @param sub_block The subblock to set the data for.
 * @param key The hexadecimal key.
 * @param key_size The size of the key in characters.
 * @return 1 if successful, 0 otherwise.
 */
int set_subblock_with_hex(SubBlock *sub_block, const char *key)
{
    // Convert hexadecimal characters to integer values and store in the subblock
    for (int i = 0; i < SUB_BLOCK_SIZE * 2; i += 2) // Key's length in hexadecimal (equals at two characters by bytes)
    {
        char hex_byte[3] = {key[i], key[i + 1], '\0'};
        sub_block->data[i / 2] = (unsigned int)strtol(hex_byte, NULL, 16);
    }

    return 1;
}

/**
 * Function to create a new block with a certain number of sub-blocks.
 *
 * @param size The number of sub-blocks in the block to be created.
 * @return A pointer to the newly created block, or NULL if memory allocation fails.
 */
Block *create_block(int size)
{
    Block *block = malloc(sizeof(Block));
    if (block == NULL)
    {
        // Handle memory allocation error
        return NULL;
    }

    block->sub_blocks = malloc(size * sizeof(SubBlock));
    if (block->sub_blocks == NULL)
    {
        // Handle memory allocation error
        free(block); // Free already allocated memory
        return NULL;
    }

    block->size = size;

    // Allocate memory for the data of each sub-block
    for (int i = 0; i < size; i++)
    {
        block->sub_blocks[i].data = malloc(SUB_BLOCK_SIZE * sizeof(unsigned int));
        if (block->sub_blocks[i].data == NULL)
        {
            // Handle memory allocation error
            // Free already allocated memory
            for (int j = 0; j < i; j++)
            {
                free(block->sub_blocks[j].data);
            }
            free(block->sub_blocks);
            free(block);
            return NULL;
        }
    }

    return block;
}

/**
 * Function to free the memory allocated for a block.
 *
 * @param block A pointer to the block whose memory is to be freed.
 */
void free_block(Block *block)
{
    if (block != NULL)
    {
        // Free the memory allocated for the data of each sub-block
        for (int i = 0; i < block->size; i++)
        {
            free(block->sub_blocks[i].data);
        }

        // Free the memory allocated for the array of sub-blocks
        free(block->sub_blocks);

        // Free the memory allocated for the block itself
        free(block);
    }
}

/**
 * Function to convert text data into blocks.
 *
 * @param text The text data to be converted into blocks.
 * @param file_size The size of the text data.
 * @return A pointer to the blocks generated from the text data.
 */
Block *text_to_blocks(const char *text, long int file_size)
{
    int num_blocks = file_size / SUB_BLOCK_SIZE;
    int padding_size = 0;

    if (file_size % SUB_BLOCK_SIZE != 0)
    {
        num_blocks++;
        padding_size = (num_blocks * SUB_BLOCK_SIZE) - file_size;
    }

    Block *blocks = create_block(num_blocks);

    int current_block = 0;
    int current_sub_block = 0;
    for (int i = 0; i < file_size; i++)
    {
        blocks->sub_blocks[current_block].data[current_sub_block] = text[i];
        current_sub_block++;

        if (current_sub_block == SUB_BLOCK_SIZE)
        {
            current_block++;
            current_sub_block = 0;
        }
    }

    for (int i = 0; i < padding_size; i++)
    {
        blocks->sub_blocks[current_block].data[current_sub_block] = '\0';
        current_sub_block++;
        if (current_sub_block == SUB_BLOCK_SIZE)
        {
            current_block++;
            current_sub_block = 0;
        }
    }

    return blocks;
}

/**
 * Function to copy data from one subblock to another.
 *
 * @param initial_subblock The initial subblock containing the data to be copied.
 * @param copied_subblock The subblock where the copied data will be stored.
 */
void subblock_copy(SubBlock *initial_subblock, SubBlock *copied_subblock)
{
    // Copy data from the initial subblock to the copied subblock
    memcpy(copied_subblock->data, initial_subblock->data, SUB_BLOCK_SIZE * sizeof(unsigned int));
}

/**
 * Function to create a new superblock with copies of a given block.
 *
 * @param original_block The block to be copied.
 * @param num_copies The number of copies of the original block to include in the superblock.
 * @return A pointer to the newly created superblock, or NULL if memory allocation fails.
 */
SuperBlock *create_superblock_with_copies(Block *original_block, int num_copies)
{
    SuperBlock *super_block = malloc(sizeof(SuperBlock));
    if (super_block == NULL)
    {
        // Handle memory allocation error
        return NULL;
    }

    super_block->blocks = malloc(num_copies * sizeof(Block));
    if (super_block->blocks == NULL)
    {
        // Handle memory allocation error
        free(super_block); // Freeing already allocated memory
        return NULL;
    }

    super_block->num_blocks = num_copies;

    // Create copies of the original block
    for (int i = 0; i < num_copies; i++)
    {
        // Allocate memory for the new block
        super_block->blocks[i].sub_blocks = malloc(original_block->size * sizeof(SubBlock));
        if (super_block->blocks[i].sub_blocks == NULL)
        {
            // Handle memory allocation error
            // Free already allocated memory
            for (int j = 0; j < i; j++)
            {
                free(super_block->blocks[j].sub_blocks);
            }
            free(super_block->blocks);
            free(super_block);
            return NULL;
        }

        // Copy the data from the original block to the new block
        super_block->blocks[i].size = original_block->size;
        for (int j = 0; j < original_block->size; j++)
        {
            super_block->blocks[i].sub_blocks[j].data = malloc(SUB_BLOCK_SIZE * sizeof(unsigned int));
            if (super_block->blocks[i].sub_blocks[j].data == NULL)
            {
                // Handle memory allocation error
                // Free already allocated memory
                for (int k = 0; k < j; k++)
                {
                    free(super_block->blocks[i].sub_blocks[k].data);
                }
                free(super_block->blocks[i].sub_blocks);
                for (int k = 0; k < i; k++)
                {
                    for (int l = 0; l < original_block->size; l++)
                    {
                        free(super_block->blocks[k].sub_blocks[l].data);
                    }
                    free(super_block->blocks[k].sub_blocks);
                }
                free(super_block->blocks);
                free(super_block);
                return NULL;
            }
            memcpy(super_block->blocks[i].sub_blocks[j].data, original_block->sub_blocks[j].data, SUB_BLOCK_SIZE * sizeof(unsigned int));
        }
    }

    return super_block;
}

/**
 * Function to create a new superblock with given blocks.
 *
 * @param blocks An array of blocks to be included in the superblock.
 * @param num_blocks The number of blocks to include in the superblock.
 * @return A pointer to the newly created superblock, or NULL if memory allocation fails.
 */
SuperBlock *create_superblock_with_blocks(Block *blocks, int num_blocks)
{
    SuperBlock *super_block = malloc(sizeof(SuperBlock));
    if (super_block == NULL)
    {
        // Handle memory allocation error
        return NULL;
    }

    super_block->blocks = malloc(num_blocks * sizeof(Block));
    if (super_block->blocks == NULL)
    {
        // Handle memory allocation error
        free(super_block); // Free already allocated memory
        return NULL;
    }

    super_block->num_blocks = num_blocks;

    // Copy the given blocks into the superblock
    for (int i = 0; i < num_blocks; i++)
    {
        super_block->blocks[i] = blocks[i];
    }

    return super_block;
}

/**
 * Function to free the memory allocated for a superblock.
 *
 * @param super_block A pointer to the superblock whose memory is to be freed.
 */
void free_superblock(SuperBlock *super_block)
{
    if (super_block != NULL)
    {
        // Free the memory allocated for the array of blocks
        for (int i = 0; i < super_block->num_blocks; i++)
        {
            for (int j = 0; j < super_block->blocks[i].size; j++)
            {
                free(super_block->blocks[i].sub_blocks[j].data);
            }
            free(super_block->blocks[i].sub_blocks);
        }
        free(super_block->blocks);

        // Free the memory allocated for the superblock itself
        free(super_block);
    }
}

/**
 * Function to print the content of a sub-block as a string.
 *
 * @param subblock A pointer to the sub-block whose content is to be printed.
 */
void print_subblock_string(SubBlock *subblock)
{
    for (int i = 0; i < SUB_BLOCK_SIZE; i++)
    {
        printf("%c", subblock->data[i]);
    }
    if (verbose)
    {
        printf("\n");
    }
}

/**
 * Function to print the content of a block as a string.
 *
 * @param blocks A pointer to the block whose content is to be printed.
 */
void print_blocks_string(Block *blocks)
{
    for (int i = 0; i < blocks->size; i++)
    {
        if (verbose)
        {
            printf("Block %d: ", i);
        }
        print_subblock_string(&(blocks->sub_blocks[i]));
    }
    if (verbose)
    {
        printf("\n");
    }
}

/**
 * Function to print the content of a sub-block in binary format.
 *
 * @param subblock A pointer to the sub-block whose content is to be printed.
 */
void print_subblock_binary(SubBlock *subblock)
{
    for (int i = 0; i < SUB_BLOCK_SIZE; i++)
    {
        for (int j = 7; j >= 0; j--)
        {
            printf("%d", (subblock->data[i] >> j) & 1);
        }
        if (verbose)
        {
            printf(" "); // Add a space between each bytes
        }
    }
}

/**
 * Function to print the content of a block in binary format.
 *
 * @param blocks A pointer to the block whose content is to be printed.
 */
void print_blocks_binary(Block *blocks)
{
    for (int i = 0; i < blocks->size; i++)
    {

        if (verbose)
        {
            printf("Block %d (binary): ", i);
        }
        print_subblock_binary(&(blocks->sub_blocks[i]));
        if (verbose)
        {
            printf("\n");
        }
    }
    printf("\n");
}

/**
 * Function to print the content of a sub-block in hexadecimal format.
 *
 * @param subblock A pointer to the sub-block whose content is to be printed.
 */
void print_subblock_hex(SubBlock *subblock)
{
    for (int i = 0; i < SUB_BLOCK_SIZE; i++)
    {
        printf("%02X ", subblock->data[i]);
    }
    if (verbose)
    {
        printf("\n");
    }
}

/**
 * Function to print the content of a block in hexadecimal format.
 *
 * @param blocks A pointer to the block whose content is to be printed.
 */
void print_blocks_hex(Block *blocks)
{
    for (int i = 0; i < blocks->size; i++)
    {
        if (verbose)
        {
            printf("Block %d (hexadecimal): ", i);
        }
        print_subblock_hex(&(blocks->sub_blocks[i]));
    }
    printf("\n");
}

/**
 * Function to print the expansion of a key in hexadecimal format.
 *
 * @param expanded_key_size The size of the expanded key array.
 * @param expanded_key A pointer to the expanded key array to be printed.
 */
void print_expanded_key_hex(int expanded_key_size, unsigned char *expanded_key)
{
    printf("Expanded key in hexa:\n");
    for (int i = 0; i < expanded_key_size; ++i)
    {
        printf("%02x", expanded_key[i]);
        if ((i + 1) % 4 == 0)
        {
            printf(" ");
            if ((i + 1) % SUB_BLOCK_SIZE == 0)
            {
                printf("\n");
            }
        }
    }
}

/**
 * Function to perform the XOR operation between a sub-block and a binary string.
 *
 * @param subblock A pointer to the sub-block.
 * @param hex_string The binary string in hexadecimal format to perform the XOR operation with.
 */
void xor_subblock(SubBlock *subblock, const char *hex_string)
{
    int hex_length = strlen(hex_string);
    if (hex_length != SUB_BLOCK_SIZE * 2)
    {
        printf("Error in xor_subblock: Hexadecimal string size (%d) must be twice the size of the sub-block (%d bytes).\n", hex_length, SUB_BLOCK_SIZE);
        return;
    }
    for (int i = 0; i < SUB_BLOCK_SIZE; i++)
    {
        char byte_string[3];                         // Store the byte in text format (e.g., "0A")
        strncpy(byte_string, &hex_string[i * 2], 2); // Extract the hexadecimal byte
        byte_string[2] = '\0';                       // Terminate the string

        unsigned int byte_value = (unsigned int)strtol(byte_string, NULL, SUB_BLOCK_SIZE); // Convert the hexadecimal byte to an integer
        subblock->data[i] ^= byte_value;                                                   // Perform the XOR operation with the sub-block
    }
}

/**
 * Function to perform the XOR operation between a block and a binary string.
 *
 * @param blocks A pointer to the block.
 * @param hex_string The binary string in hexadecimal format to perform the XOR operation with.
 */
void xor_blocks(Block *blocks, const char *hex_string)
{
    for (int i = 0; i < blocks->size; i++)
    {
        xor_subblock(&(blocks->sub_blocks[i]), hex_string);
    }
}

/**
 * Function to perform bitwise XOR operation between corresponding bytes of two subblocks.
 *
 * @param initial_subblock The initial subblock containing the original data.
 * @param modified_subblock The modified subblock where the result of the XOR operation will be stored.
 */
void xor_subblock_subblock(const SubBlock *initial_subblock, SubBlock *modified_subblock)
{
    // Iterate over each byte (or element) of the sub-blocks
    for (int i = 0; i < SUB_BLOCK_SIZE; i++)
    {
        // Perform the XOR operation between corresponding bytes
        modified_subblock->data[i] ^= initial_subblock->data[i];
    }
}

/**
 * Function to perform the XOR operation between a sub-block and an array of unsigned characters representing a binary string.
 *
 * @param subblock A pointer to the sub-block.
 * @param hex_string An array of unsigned characters representing the binary string in hexadecimal format to perform the XOR operation with.
 */
void xor_subblock_unsigned(SubBlock *subblock, const unsigned char *hex_string)
{
    // Iterate over each byte of the hexadecimal string
    for (int i = 0; i < SUB_BLOCK_SIZE; i++)
    {
        // Convert the hexadecimal byte to an unsigned integer
        unsigned int byte_value = (unsigned int)hex_string[i]; // Directly read each byte of the hexadecimal string

        // Perform the XOR operation with the sub-block
        subblock->data[i] ^= byte_value;
    }
}

/**
 * Function to perform the XOR operation between a block and an array of unsigned characters representing a binary string.
 *
 * @param blocks A pointer to the block.
 * @param hex_string An array of unsigned characters representing the binary string in hexadecimal format to perform the XOR operation with.
 */
void xor_blocks_unsigned(Block *blocks, const unsigned char *hex_string)
{
    for (int i = 0; i < blocks->size; i++)
    {
        xor_subblock_unsigned(&(blocks->sub_blocks[i]), hex_string);
    }
}

/**
 * Function to perform addition with carry directly on the modified subblock using data from the initial subblock.
 *
 * @param initial_subblock The subblock containing the original data to be added.
 * @param modified_subblock The subblock to which the data from the initial subblock will be added, and where the result will be stored.
 */
void add_subblock_subblock(const SubBlock *initial_subblock, SubBlock *modified_subblock)
{
    uint16_t carry = 0;                           // Start with no carry
    for (int i = SUB_BLOCK_SIZE - 1; i >= 0; i--) // Start from the least significant byte
    {
        uint16_t sum = (uint16_t)modified_subblock->data[i] + (uint16_t)initial_subblock->data[i] + carry; // Cast to uint16_t to prevent overflow
        modified_subblock->data[i] = (unsigned char)(sum & 0xFF);                                          // Store the lower 8 bits in the modified subblock
        carry = sum >> 8;                                                                                  // Update carry for the next byte
    }
}

/**
 * Deprecated fonction (very slow)
 * Function to multiply two numbers in the Galois Field GF(2^8).
 *
 * @param a The first number to be multiplied.
 * @param b The second number to be multiplied.
 * @return The result of the multiplication.
 */
unsigned char multiply_old(unsigned char a, unsigned char b)
{
    unsigned char result = 0;
    unsigned char high_bit_set;
    for (int i = 0; i < 8; i++)
    {
        if (b & 1)
        {
            result ^= a;
        }
        high_bit_set = (a & 0x80);
        a <<= 1;
        if (high_bit_set)
        {
            a ^= 0x1B; // Reducing polynomial: x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    return result;
}

// Include the multiplication tables
extern const unsigned char gf_mul_by_2[];
extern const unsigned char gf_mul_by_3[];
extern const unsigned char gf_mul_by_9[];
extern const unsigned char gf_mul_by_11[];
extern const unsigned char gf_mul_by_13[];
extern const unsigned char gf_mul_by_14[];

/**
 * Function to multiply two numbers in the Galois Field GF(2^8).
 *
 * @param a The first number to be multiplied.
 * @param b The second number to be multiplied.
 * @return The result of the multiplication.
 */
unsigned char multiply(unsigned char a, unsigned char b)
{
    switch (a)
    {
    case 0x01:
        return b;
    case 0x02:
        return gf_mul_by_2[b];
    case 0x03:
        return gf_mul_by_3[b];
    case 0x09:
        return gf_mul_by_9[b];
    case 0x0B:
        return gf_mul_by_11[b];
    case 0x0D:
        return gf_mul_by_13[b];
    case 0x0E:
        return gf_mul_by_14[b];
    default:
        printf("%d\n", b);
        return 0;
    }
}

// Convert SubBlock to two 64-bit integers for easier manipulation, bit by bit
void subblock_to_uint64(const SubBlock *sb, uint64_t out[2])
{
    // Reset the output array
    out[0] = 0;
    out[1] = 0;

    // We are assuming that the subblock data has at least 4 integers if SUB_BLOCK_SIZE is 16 and each unsigned int is 4 bytes
    for (int i = 0; i < 16; i++)
    {
        if (i < 8)
        {
            // Store the first two integers in the first 64 bits
            out[0] |= ((uint64_t)sb->data[i]) << (i * 8);
        }
        else
        {
            // Store the next two integers in the next 64 bits
            out[1] |= ((uint64_t)sb->data[i]) << ((i - 8) * 8);
        }
    }
}

/**
 * Function to convert two 64-bit integers back to a subblock.
 *
 * @param in Array containing two 64-bit unsigned integers.
 * @param sb Pointer to the subblock to be filled with data.
 */
void uint64_to_subblock(SubBlock *sb, const uint64_t in[2])
{
    for (int i = 0; i < 16; i++)
    {
        if (i < 8)
        {
            // Retrieve the first 64 bits data, byte by byte
            sb->data[i] = (unsigned int)((in[0] >> (i * 8)) & 0xFF);
        }
        else
        {
            // Retrieve the next 64 bits data, byte by byte
            sb->data[i] = (unsigned int)((in[1] >> ((i - 8) * 8)) & 0xFF);
        }
    }
}

/**
 * Function to print the 128-bit data stored in two 64-bit integers in binary format, with spaces between bytes.
 *
 * @param out Array containing two 64-bit unsigned integers.
 */
void print_uint64_binary(const uint64_t out[2])
{
    // Iterate over each bit of the two 64-bit integers
    for (int i = 1; i >= 0; i--)
    { // Iterate over each 64-bit integer
        for (int j = 63; j >= 0; j--)
        { // Iterate over each bit in the 64-bit integer
            // Print each bit, with a space every 8 bits
            printf("%ld", (out[i] >> j) & 1);
            if (j % 8 == 0 && j != 0)
            {
                printf(" "); // Insert space between bytes
            }
        }
        if (i > 0)
        {
            printf(" "); // Space between the two 64-bit integers
        }
    }
    printf("\n");
}

/**
 * Multiplies two sub-blocks within GF(2^128).
 *
 * @param a SubBlock pointer to the first sub-block (also where result is stored).
 * @param b SubBlock pointer to the second sub-block.
 */
void multiply_uint(SubBlock *a, SubBlock *b)
{
    uint64_t a64[2], b64[2], result[2] = {0};
    uint64_t mask = 0x8000000000000000;

    subblock_to_uint64(a, a64);
    subblock_to_uint64(b, b64);

    for (int i = 0; i < 128; i++)
    {
        if ((b64[i / 64] >> (i % 64)) & 1)
        {
            result[0] ^= a64[0];
            result[1] ^= a64[1];
        }

        uint64_t carry = a64[1] & mask;
        a64[1] = (a64[1] << 1) | (a64[0] >> 63);
        a64[0] <<= 1;

        if (carry)
        { // If out of bounds, apply the reduction polynomial x^128 + x^7 + x^2 + x + 1
            a64[0] ^= 0x87;
        }
    }

    uint64_to_subblock(a, result);
}