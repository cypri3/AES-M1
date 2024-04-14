#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "utils.h"

#define MAX_KEY_SIZE 48 + 1 // Taille maximale en octets (256 bits + les \0 qui doivent être pris en compte pour le C)
#define BLOCK_SIZE 128
#define SUB_BLOCK_SIZE 16
/**
 * Function to print the help when '-h' character is read
 */
void print_help(int page)
{
    if (page == 1)
    {
        printf("\nHelp page 1/2:\n\n");
        printf("Usage: ./AES [-b | -o FILE | -m MODE | -h]\n");
        printf("./AES [-g SIZE | -k KEY | -o FILE | -h]\n");
        printf("Encrypt or decrypt files using AES with specified mode and key\n");
        printf("-m MODE, --mode MODE           set the mode of operation (ECB, CBC, CFB, GCM)\n");
        printf("-k KEY, --key KEY              set the encryption/decryption key in hexadecimal format\n");
        printf("-g SIZE, --generate SIZE       generate a random key of the specified size (128, 192, 256)\n");
        printf("-o FILE, --output FILE         specify the output file\n");
        printf("-h, --help                     display this help message\n");
        printf("-b, --benchmark                perform a benchmark\n");
        printf("-c, --cipher                   perform encryption\n");
        printf("-d, --decipher                 perform decryption\n");
        printf("\nFor additional information, try ./AES -h 2\n\n");
    }
    else if (page == 2)
    {
        printf("\nHelp page 2/2:\n\n");
        printf("Examples of commands formatting:\n");
        printf("./AES -m ECB -k 0x000102030405060708090a0b0c0d0e0f -o encrypted_file.txt original_file.txt\n");
        printf("./AES -m CBC -k 0x000102030405060708090a0b0c0d0e0f -o encrypted_file.txt original_file.txt\n");
        printf("./AES -m CFB -k 0x000102030405060708090a0b0c0d0e0f -o encrypted_file.txt original_file.txt\n");
        printf("./AES -m GCM -k 0x000102030405060708090a0b0c0d0e0f -o encrypted_file.txt original_file.txt\n");
        printf("./AES -g 256 -o generated_key.txt\n");
        printf("./AES -b\n");
        printf("./AES -c -k 0x000102030405060708090a0b0c0d0e0f -o encrypted_file.txt original_file.txt\n");
        printf("./AES -d -k 0x000102030405060708090a0b0c0d0e0f -o decrypted_file.txt encrypted_file.txt\n");
        printf("\nFor more options, try ./AES -h 1\n\n");
    }
    else
    {
        printf("Invalid help page number.\n");
    }
}

unsigned char Rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

// Définition de la Rijndael S-box
// Il faut bien mettre le unsigned sinon on passe d'un écriture du type 82 à FFFFFF82
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
 * NR : Nombre de tours pour l'AES-X
 */
void KeyExpansion(const char *key, const int key_size, unsigned char *expanded_key, int Nr)
{
    int keySize = key_size / 8; // Variable key_size / 8 ici pour ne pas faire trop de disivion par 8 dans le reste de la fonction
    int i, j, k;
    unsigned char temp[4];

    // La première partie de la clé d'expansion est la clé d'origine
    for (i = 0; i < keySize; ++i)
    {

        char byte_string[3];                  // Stocke le byte en format texte (ex: "0A")
        strncpy(byte_string, &key[i * 2], 2); // Extraire le byte hexadécimal
        byte_string[2] = '\0';                // Terminer la chaîne de caractères

        unsigned int byte_value = (unsigned int)strtol(byte_string, NULL, SUB_BLOCK_SIZE); // Convertir le byte hexadécimal en entier
        expanded_key[i] = byte_value;                                                      // Effectuer l'opération XOR avec le sous-bloc
    }

    // Les mots de clé restants de l'expansion de clé
    for (i = keySize; i < (Nr + 1) * SUB_BLOCK_SIZE; i += 4)
    {
        for (j = 0; j < 4; ++j)
        {
            temp[j] = expanded_key[i - 4 + j];
        }
        if (i % keySize == 0)
        {
            // Effectue RotWord() sur temp
            unsigned char t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // Effectue SubWord() sur temp
            for (j = 0; j < 4; ++j)
            {
                temp[j] = SBox[temp[j] >> 4][temp[j] & 0x0F];
            }

            // XOR avec Rcon
            temp[0] ^= Rcon[i / keySize];
        }
        else if (keySize > 24 && i % keySize == 16)
        {
            // Effectue SubWord() sur temp
            for (j = 0; j < 4; ++j)
            {
                temp[j] = SBox[temp[j] >> 4][temp[j] & 0x0F];
            }
        }

        // XOR avec le mot de la clé précédente
        for (k = 0; k < 4; ++k)
        {
            expanded_key[i + k] = expanded_key[i + k - keySize] ^ temp[k];
        }
    }
}

// Fonction pour appliquer la SubBytes
void SubBytes(SubBlock *subblock)
{
    for (int i = 0; i < SUB_BLOCK_SIZE; i++)
    {
        int row = (subblock->data[i] >> 4) & 0x0F; // Extraction de la ligne
        int col = subblock->data[i] & 0x0F;        // Extraction de la colonne
        subblock->data[i] = SBox[row][col];        // Remplacement par la valeur de la S-box
    }
}

// Fonction pour appliquer la SubBytes à tout un bloc
void SubBytesBlock(Block *block)
{
    for (int i = 0; i < block->size; i++)
    {
        SubBytes(&(block->sub_blocks[i]));
    }
}

// Fonction pour appliquer l'inverse de SubBytes
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
        int row = (subblock->data[i] >> 4) & 0x0F;   // Extraction de la ligne
        int col = subblock->data[i] & 0x0F;          // Extraction de la colonne
        subblock->data[i] = inverse_s_box[row][col]; // Remplacement par la valeur de l'inverse S-box
    }
}

// Fonction pour appliquer l'inverse de SubBytes à tout un bloc
void InvSubBytesBlock(Block *block)
{
    for (int i = 0; i < block->size; i++)
    {
        InvSubBytes(&(block->sub_blocks[i]));
    }
}

// Fonction pour effectuer l'opération ShiftRows sur un sous-bloc
void ShiftRows(SubBlock *subblock)
{
    // Shift des rangées du sous-bloc
    for (int i = 1; i < 4; i++)
    {
        // Nombre de décalages à effectuer pour la rangée actuelle
        int shift_amount = i;

        // Décalage circulaire des éléments dans la rangée
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

// Fonction pour appliquer l'opération ShiftRows à tous les sous-blocs d'un bloc
void ShiftRowsBlock(Block *block)
{
    // Application de ShiftRows à chaque sous-bloc
    for (int i = 0; i < block->size; i++)
    {
        ShiftRows(&(block->sub_blocks[i]));
    }
}

// Fonction pour effectuer l'opération InvShiftRows sur un sous-bloc
void InvShiftRows(SubBlock *subblock)
{
    // Shift inverse des rangées du sous-bloc
    for (int i = 1; i < 4; i++)
    {
        // Nombre de décalages à effectuer pour la rangée actuelle
        int shift_amount = i;

        // Décalage circulaire inverse des éléments dans la rangée
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

// Fonction pour appliquer l'opération InvShiftRows à tous les sous-blocs d'un bloc
void InvShiftRowsBlock(Block *block)
{
    // Application de InvShiftRows à chaque sous-bloc
    for (int i = 0; i < block->size; i++)
    {
        InvShiftRows(&(block->sub_blocks[i]));
    }
}

// Fonction pour appliquer l'opération MixColumns à un sous-bloc
void MixColumns(SubBlock *subblock)
{
    unsigned int temp[4];

    // Opération MixColumns sur chaque colonne
    for (int i = 0; i < 4; i++)
    {
        temp[0] = subblock->data[i];
        temp[1] = subblock->data[i + 4];
        temp[2] = subblock->data[i + 8];
        temp[3] = subblock->data[i + 12];

        subblock->data[i] = multiply(temp[0], 2) ^ multiply(temp[1], 3) ^ temp[2] ^ temp[3];
        subblock->data[i + 4] = temp[0] ^ multiply(temp[1], 2) ^ multiply(temp[2], 3) ^ temp[3];
        subblock->data[i + 8] = temp[0] ^ temp[1] ^ multiply(temp[2], 2) ^ multiply(temp[3], 3);
        subblock->data[i + 12] = multiply(temp[0], 3) ^ temp[1] ^ temp[2] ^ multiply(temp[3], 2);
    }
}

// Fonction pour appliquer l'opération MixColumns à un bloc de sous-blocs
void MixColumnsBlock(Block *block)
{
    for (int i = 0; i < block->size; i++)
    {
        MixColumns(&(block->sub_blocks[i]));
    }
}

// Fonction pour appliquer l'opération MixColumns à un bloc de sous-blocs
void MixColumnsBlock2(Block *block)
{
    // Matrice de transformation MixColumns
    unsigned char mix_columns_matrix[4][4] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}};

    for (int i = 0; i < block->size; i++)
    {
        for (int j = 0; j < SUB_BLOCK_SIZE; j++)
        {
            unsigned char result = 0;
            for (int k = 0; k < SUB_BLOCK_SIZE; k++)
            {
                result ^= multiply(mix_columns_matrix[j][k], block->sub_blocks[i].data[k]);
            }
            block->sub_blocks[i].data[j] = result;
        }
    }
}

// Fonction pour appliquer l'opération InvMixColumns à un sous-bloc
void InvMixColumns(SubBlock *subblock)
{
    unsigned int temp[4];

    // Opération InvMixColumns sur chaque colonne
    for (int i = 0; i < 4; i++)
    {
        temp[0] = subblock->data[i];
        temp[1] = subblock->data[i + 4];
        temp[2] = subblock->data[i + 8];
        temp[3] = subblock->data[i + 12];

        subblock->data[i] = multiply(temp[0], 0x0E) ^ multiply(temp[1], 0x0B) ^ multiply(temp[2], 0x0D) ^ multiply(temp[3], 0x09);
        subblock->data[i + 4] = multiply(temp[0], 0x09) ^ multiply(temp[1], 0x0E) ^ multiply(temp[2], 0x0B) ^ multiply(temp[3], 0x0D);
        subblock->data[i + 8] = multiply(temp[0], 0x0D) ^ multiply(temp[1], 0x09) ^ multiply(temp[2], 0x0E) ^ multiply(temp[3], 0x0B);
        subblock->data[i + 12] = multiply(temp[0], 0x0B) ^ multiply(temp[1], 0x0D) ^ multiply(temp[2], 0x09) ^ multiply(temp[3], 0x0E);
    }
}

// Fonction pour appliquer l'opération InvMixColumns à un bloc de sous-blocs
void InvMixColumnsBlock(Block *block)
{
    for (int i = 0; i < block->size; i++)
    {
        InvMixColumns(&(block->sub_blocks[i]));
    }
}

// Fonction pour appliquer l'opération InvMixColumns à un bloc de sous-blocs
void InvMixColumnsBlock2(Block *block)
{
    // Matrice de transformation InvMixColumns
    unsigned char inv_mix_columns_matrix[4][4] = {
        {0x0E, 0x0B, 0x0D, 0x09},
        {0x09, 0x0E, 0x0B, 0x0D},
        {0x0D, 0x09, 0x0E, 0x0B},
        {0x0B, 0x0D, 0x09, 0x0E}};

    for (int i = 0; i < block->size; i++)
    {
        for (int j = 0; j < SUB_BLOCK_SIZE; j++)
        {
            unsigned char result = 0;
            for (int k = 0; k < SUB_BLOCK_SIZE; k++)
            {
                result ^= multiply(inv_mix_columns_matrix[j][k], block->sub_blocks[i].data[k]);
            }
            block->sub_blocks[i].data[j] = result;
        }
    }
}

// Fonction pour appliquer l'opération AddRoundKey à un sous-bloc avec une clé donnée
void AddRoundKey(SubBlock *subblock, const char *key, int key_size)
{
    if (key_size / 8 != BLOCK_SIZE / 8)
    {
        printf("Error: Key size does not match the size of the sub-block.\n");
        return;
    }

    for (int i = 0; i < key_size / 8; i++)
    {
        subblock->data[i] ^= key[i];
    }
}

// Fonction pour appliquer l'opération AddRoundKey à tout un bloc avec une clé donnée
void AddRoundKeyBlock(Block *block, const char *key, int key_size)
{
    if (key_size / 8 != BLOCK_SIZE / 8)
    {
        printf("Error: Key size does not match the size of the sub-blocks in the block.\n");
        return;
    }

    for (int i = 0; i < block->size; i++)
    {
        for (int j = 0; j < SUB_BLOCK_SIZE; j++)
        {
            block->sub_blocks[i].data[j] ^= key[j];
        }
    }
}

int main(int argc, char *argv[])
{
    int opt;
    int option_index = 0;
    int help_page = 1;

    int key_size = 128;                              // Taille de la clé en bits (128, 192 ou 256)
    char key[MAX_KEY_SIZE];                          // Stockage de la clé générée
    strcpy(key, "000102030405060708090a0b0c0d0e0f"); // Définir la valeur par défaut de key
    // Flags for options
    char *output_file = NULL;
    FILE *output;
    int mode_selected = 0;
    char *mode = 0;

    // Flags to determine the execution mode
    int is_solver = 2;
    bool is_benchmark = false;
    bool is_generator = NULL;

    // Structure décrivant les options longues
    static struct option long_options[] = {
        {"mode", required_argument, 0, 'm'},
        {"key", required_argument, 0, 'k'},
        {"generate", required_argument, 0, 'g'},
        {"output", required_argument, 0, 'o'},
        {"help", required_argument, 0, 'h'},
        {"benchmark", no_argument, 0, 'b'},
        {"cipher", no_argument, 0, 'c'},
        {"decipher", no_argument, 0, 'd'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long_only(argc, argv, "m:g:o:h:b", long_options, &option_index)) != -1)
    {
        switch (opt)
        {
        case 'm':
            printf("Option -m (mode) with value: %s\n", optarg);
            mode = optarg;
            if (strcmp(mode, "ECB") == 0)
            {
                mode_selected = 0;
            }
            else if (strcmp(mode, "CBC") == 0)
            {
                mode_selected = 1;
            }
            else if (strcmp(mode, "CFB") == 0)
            {
                mode_selected = 2;
            }
            else if (strcmp(mode, "GCM") == 0)
            {
                mode_selected = 3;
            }
            else
            {
                printf("Invalid mode: ECB, CBC, CFB or GCM required.\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'k':
            printf("Option -k (key) with value: %s\n", optarg);
            if (strncmp(optarg, "0x", 2) == 0)
            {
                strcpy(key, optarg + 2); // Copier optarg sans les deux premiers caractères ("0x")
            }
            else
            {
                strcpy(key, optarg); // Copier optarg tel quel
            }
            key_size = strlen(key) * 4; // Défintion de la taille de la clé

            if (!validate_key(key))
            {
                printf("Invalid key: %s\n", key);
            }
            break;
        case 'g':
            printf("Option -g (generate) with value: %s\n", optarg);
            int size = atoi(optarg);
            if (size == 128 || size == 192 || size == 256)
            {
                key_size = size;
            }
            else
            {
                printf("Invalid key size: %s\n128,192 or 256 needed.\n", key);
                exit(EXIT_FAILURE);
            }
            is_generator = true; // Set the generator mode flag
            break;
        case 'o':
            printf("Option -o (output) with value: %s\n", optarg);
            output_file = optarg;
            break;
        case 'h':
            if (optarg != NULL && optarg[0] >= '0' && optarg[0] <= '9')
            {
                help_page = atoi(optarg);
            }
            print_help(help_page);
            exit(EXIT_SUCCESS);
            break;
        case 'b': // Benchmark
            printf("Option -b (benchmark) selected\n");
            is_benchmark = true;
            break;
        case 'c':
            if (is_solver == 2)
            {
                printf("Option -c (cipher) selected\n");
                is_solver = false;
            }
            else if (is_solver == 1)
            {
                printf("Incompatible selection for -c and -d\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 'd':
            if (is_solver == 2)
            {
                printf("Option -d (decrypt) selected\n");
                is_solver = true;
            }
            else if (is_solver == 0)
            {
                printf("Incompatible selection for -c and -d\n");
                exit(EXIT_FAILURE);
            }
            break;
        case 0:
            // A long option has been encounter
            if (long_options[option_index].flag != 0)
            {
                printf("Option %s selected\n", long_options[option_index].name);
            }
            break;
        default:
            fprintf(stderr, "Invalid option\n");
            print_help(1);
            exit(EXIT_FAILURE);
            break;
        }
    }

    // Handle output file if specified
    if (output_file != NULL)
    {
        output = fopen(output_file, "w");
        if (output == NULL)
        {
            perror("Failed to open output file");
            exit(EXIT_FAILURE);
        }
        // Allows writing all subsequent outputs into the file
        if (dup2(fileno(output), STDOUT_FILENO) == -1)
        {
            perror("Failed to redirect stdout");
            fclose(output);
            exit(EXIT_FAILURE);
        }
        fclose(output);
    }

    if (is_benchmark)
    {
        exit(EXIT_SUCCESS);
    }

    // Determine the execution mode
    if (optind < argc) // TODO verif
    {
        is_solver = true; // Set the solver mode flag
    }

    // Lire le contenu du fichier spécifié en argument
    for (int i = optind; i < argc; i++) // TODO faire une erreur si on est dans un mode solver / non Solveur et pas de fichier donné
    {
        printf("Reading file: %s\n", argv[i]);
        char *file_content = read_file(argv[i]);
        printf("File content:\n%s\n", file_content);

        // Convertir le texte en blocs
        Block *blocks = text_to_blocks(file_content);

        if (is_solver == 1)
        {
            printf("Decryption mode\n");

            int expanded_key_size, Nr;
            if (key_size == 128)
            {
                Nr = 10;
                expanded_key_size = 176;
            }
            else if (key_size == 192)
            {
                Nr = 12;
                expanded_key_size = 208;
            }
            else
            {
                Nr = 14;
                expanded_key_size = 240;
            }
            unsigned char expanded_key[expanded_key_size];

            printf("key size : %d\n", key_size);
            KeyExpansion(key, key_size, expanded_key, Nr);
            // Affichage de la clé d'expansion
            print_expanded_key_hex(expanded_key_size, expanded_key); // TODO mettre un mode verbose ?

            // ---------- Actuelement partie de tests ------------//

            if (mode_selected == 0)
            {
                unsigned char temp_key[SUB_BLOCK_SIZE];
                for (int round = 0; round < Nr; round++)
                {
                    memcpy(temp_key, &(expanded_key[round * SUB_BLOCK_SIZE]), SUB_BLOCK_SIZE);
                    // Effectuer le XOR entre la clé et les blocs
                    xor_blocks_with_key(blocks, temp_key);
                    printf("\n\n\n\n");
                    for (int i = 0; i < SUB_BLOCK_SIZE; ++i)
                    {
                        printf("%02x ", temp_key[i]);
                    }
                    printf("\n\n\n\n");

                    // Appliquer SubBytes
                    SubBytesBlock(blocks);
                }
                // Affichage des blocs sous forme de texte
                printf("Text as blocks after SubBytes \n");
                print_blocks_string(blocks);

                // Affichage des blocs sous forme binaire
                printf("Text as binary blocks after SubBytes \n");
                print_blocks_binary(blocks);

                // Affichage des blocs sous forme hexadécimale
                printf("Text as hex blocks after SubBytes \n");
                print_blocks_hex(blocks);

                // Effectuer le XOR entre la clé et les blocs pour revenir à l'état initial
                // xor_blocks_with_key(blocks, &(expanded_key[round * SUB_BLOCK_SIZE]));

                // Affichage des blocs sous forme de texte
                printf("Text as blocks after XOR \n");
                print_blocks_string(blocks);

                // Affichage des blocs sous forme binaire
                printf("Text as binary blocks after XOR \n");
                print_blocks_binary(blocks);
            }
            else if (mode_selected == 1)
            {
                // CBC
            }
            else if (mode_selected == 2)
            {
                // CFB
            }
            else
            {
                // GCM
            }

            free_block(blocks);
            free(file_content); // Libérer la mémoire allouée pour le contenu du fichier
        }
        else if (is_solver == 0)
        {
            printf("Encryption mode\n");
            if (mode_selected == 0)
            {
                // ECB
            }
            else if (mode_selected == 1)
            {
                // CBC
            }
            else if (mode_selected == 2)
            {
                // CFB
            }
            else
            {
                // GCM
            }
        }
    }

    if (is_generator)
    {
        // Initialiser le générateur de nombres aléatoires
        srand(time(NULL));

        // Générer la clé aléatoire
        generate_random_key(key_size, key);

        // Afficher la clé générée
        printf("Clé générée (en hexadécimal) : 0x");
        for (int i = 0; i < key_size / 8; i++)
        {
            printf("%02x", key[i] & 0xFF); // Afficher chaque octet de la clé en hexadécimal
        }
        printf("\n");
    }
    return 0;
}

int main2()
{
    // Vérifier sur https://www.cryptool.org/en/cto/aes-step-by-step
    // On devrait trouver

    // 2b7e1516 28aed2a6 abf71588 09cf4f3c
    // a0fafe17 88542cb1 23a33939 2a6c7605
    // f2c295f2 7a96b943 5935807a 7359f67f
    // 3d80477d 4716fe3e 1e237e44 6d7a883b
    // ef44a541 a8525b7f b671253b db0bad00
    // d4d1c6f8 7c839d87 caf2b8bc 11f915bc
    // 6d88a37a 110b3efd dbf98641 ca0093fd
    // 4e54f70e 5f5fc9f3 84a64fb2 4ea6dc4f
    // ead27321 b58dbad2 312bf560 7f8d292f
    // ac7766f3 19fadc21 28d12941 575c006e
    // d014f9a8 c9ee2589 e13f0cc8 b6630ca6

    const char *key = "2b7e151628aed2a6abf7158809cf4f3c";
    // const char *key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    //  const char *key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    int key_size = strlen(key) * 4; // Convertir de la longueur hexadécimale à la longueur en octets
    int expanded_key_size, Nr;
    if (key_size == 128)
    {
        Nr = 10;
        expanded_key_size = 176;
    }
    else if (key_size == 192)
    {
        Nr = 12;
        expanded_key_size = 208;
    }
    else
    {
        Nr = 14;
        expanded_key_size = 240;
    }
    unsigned char expanded_key[expanded_key_size];

    printf("key size : %d\n", key_size);
    KeyExpansion(key, key_size, expanded_key, Nr);
    // Affichage de la clé d'expansion
    print_expanded_key_hex(expanded_key_size, expanded_key);

    return 0;
}