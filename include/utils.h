#ifndef UTILS_H
#define UTILS_H
#include <stdbool.h>
extern int key_size;
extern int verbose;

typedef struct
{
    unsigned int *data; // Array of data for the sub-block
} SubBlock;

typedef struct
{
    SubBlock *sub_blocks; // Array of sub-blocks
    int size;             // Number of sub-blocks
} Block;

typedef struct
{
    Block *blocks;  // Array of blocks
    int num_blocks; // Number of blocks
} SuperBlock;

int valid_key(const char *key);
int valid_IV(const char *IV);
int valid_auth_data(char *auth_data);

void generate_random_key(int key_size, char *key);
char *read_file(const char *filename, long int *file_size, bool as_hexadecimal);

SubBlock *create_subblock();
void free_subblock(SubBlock *subblock);

int set_subblock_with_hex(SubBlock *sub_block, const char *key);

Block *create_block(int size);
void free_block(Block *block);
Block *text_to_blocks(const char *text, long int file_size);

void subblock_copy(SubBlock *initial_subblock, SubBlock *copied_subblock);

SuperBlock *create_superblock_with_copies(Block *original_block, int num_copies);
SuperBlock *create_superblock_with_blocks(Block *blocks, int num_blocks);
void free_superblock(SuperBlock *super_block);

void print_subblock_string(SubBlock *subblock);
void print_blocks_string(Block *blocks);

void print_subblock_binary(SubBlock *subblock);
void print_blocks_binary(Block *blocks);

void print_subblock_hex(SubBlock *subblock);
void print_blocks_hex(Block *block);

void print_expanded_key_hex(int expanded_key_size, unsigned char *expanded_key);

void xor_subblock(SubBlock *subblock, const char *binary_string);
void xor_blocks(Block *blocks, const char *hex_string);

void xor_subblock_subblock(const SubBlock *initial_subblock, SubBlock *modified_subblock);

void xor_subblock_unsigned(SubBlock *subblock, const unsigned char *hex_string);
void xor_blocks_unsigned(Block *blocks, const unsigned char *hex_string);

void add_subblock_subblock(const SubBlock *initial_subblock, SubBlock *modified_subblock);

unsigned char multiply_old(unsigned char a, unsigned char b);
unsigned char multiply(unsigned char a, unsigned char b);
void multiply_uint(SubBlock *a, SubBlock *b);

#endif /* UTILS_H */