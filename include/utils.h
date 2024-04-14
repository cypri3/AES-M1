#ifndef UTILS_H
#define UTILS_H
extern int key_size;

typedef struct
{
    unsigned int *data; // Tableau de données du sous-bloc
} SubBlock;

typedef struct
{
    SubBlock *sub_blocks; // Tableau de sous-blocs
    int size;             // Nombre de sous-blocs
} Block;

int validate_key(const char *key);
void generate_random_key(int key_size, char *key);
char *read_file(const char *filename);

Block *create_block(int size);
void free_block(Block *block);
Block *text_to_blocks(const char *text);

void print_subblock_string(SubBlock *subblock);
void print_blocks_string(Block *blocks);

void print_subblock_binary(SubBlock *subblock);
void print_blocks_binary(Block *blocks);

void print_subblock_hex(SubBlock *subblock);
void print_blocks_hex(Block *block);

void print_expanded_key_hex(int expanded_key_size, unsigned char *expanded_key);

void xor_subblock(SubBlock *subblock, const char *binary_string);
void xor_blocks_with_key(Block *blocks, const char *key);

unsigned int multiply(unsigned int a, unsigned int b);

#endif /* UTILS_H */