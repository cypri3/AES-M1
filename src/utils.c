#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "utils.h"
#include <ctype.h> // Bibliothèque de tests pour les clés

#define BLOCK_SIZE 128
#define SUB_BLOCK_SIZE 16

/**
 * This function checks if a key matches the flowwoling conditions :
 * - an hexadicimal key
 * - a 128, 192 or 256 bits key
 * @param key The key to test.
 * @return 1 if the size is valid, 0 otherwise.
 */
int validate_key(const char *key)
{
    // Vérifier que la longueur de la clé est valide (32, 48 ou 64 caractères)
    size_t len = strlen(key);
    if (len != 32 && len != 48 && len != 64)
    {
        return 0;
    }

    // Vérifier que tous les caractères sont valides (chiffres de 0 à 9 et lettres de a à f)
    for (size_t i = 2; i < len; i++)
    {
        if (!isxdigit(key[i])) // Vérification hexa (1-9 A-F a-f)
        {
            return 0;
        }
    }

    return 1;
}

/**
 * TODO
 */
void generate_random_key(int key_size, char *key)
{
    // Définir la taille en octets
    int size_in_bytes = key_size / 8;

    // Générer une clé aléatoire
    for (int i = 0; i < size_in_bytes; i++)
    {
        key[i] = rand() % 256; // Générer un octet aléatoire
    }
}

/**
 * TODO
 */
char *read_file(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        fprintf(stderr, "Failed to open file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    // Trouver la taille du fichier
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allouer de la mémoire pour contenir le contenu du fichier
    char *file_content = (char *)malloc(file_size + 1);
    if (file_content == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    // Lire le contenu du fichier
    size_t bytes_read = fread(file_content, 1, file_size, file);
    if ((long int)bytes_read != file_size)
    {
        fprintf(stderr, "Failed to read file %s\n", filename);
        fclose(file);
        free(file_content);
        exit(EXIT_FAILURE);
    }

    // Ajouter un caractère de fin de chaîne
    file_content[file_size] = '\0';

    // Fermer le fichier
    fclose(file);

    return file_content;
}

// Fonction pour créer un nouveau bloc avec un certain nombre de sous-blocs
Block *create_block(int size)
{
    Block *block = malloc(sizeof(Block));
    if (block == NULL)
    {
        // Gestion de l'erreur d'allocation de mémoire
        return NULL;
    }

    block->sub_blocks = malloc(size * sizeof(SubBlock));
    if (block->sub_blocks == NULL)
    {
        // Gestion de l'erreur d'allocation de mémoire
        free(block); // Libération de la mémoire déjà allouée
        return NULL;
    }

    block->size = size;

    // Allocation de mémoire pour les données de chaque sous-bloc
    for (int i = 0; i < size; i++)
    {
        block->sub_blocks[i].data = malloc(SUB_BLOCK_SIZE * sizeof(unsigned int));
        if (block->sub_blocks[i].data == NULL)
        {
            // Gestion de l'erreur d'allocation de mémoire
            // Libération de la mémoire déjà allouée
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

// Fonction pour libérer la mémoire allouée pour un bloc
void free_block(Block *block)
{
    if (block != NULL)
    {
        // Libérer la mémoire allouée pour les données de chaque sous-bloc
        for (int i = 0; i < block->size; i++)
        {
            free(block->sub_blocks[i].data);
        }

        // Libérer la mémoire allouée pour le tableau de sous-blocs
        free(block->sub_blocks);

        // Libérer la mémoire allouée pour le bloc lui-même
        free(block);
    }
}

Block *text_to_blocks(const char *text)
{
    int text_length = strlen(text);
    int num_blocks = text_length / SUB_BLOCK_SIZE;
    int padding_size = 0;

    if (text_length % SUB_BLOCK_SIZE != 0)
    {
        num_blocks++;
        padding_size = (num_blocks * SUB_BLOCK_SIZE) - text_length;
    }

    Block *blocks = create_block(num_blocks);

    int current_block = 0;
    int current_sub_block = 0;
    for (int i = 0; i < text_length; i++)
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

// Fonction pour afficher le contenu d'un sous-bloc en string
void print_subblock_string(SubBlock *subblock)
{
    for (int i = 0; i < SUB_BLOCK_SIZE; i++)
    {
        printf("%c", subblock->data[i]);
    }
    printf("\n");
}

// Fonction pour afficher le contenu d'un bloc en string
void print_blocks_string(Block *blocks)
{
    for (int i = 0; i < blocks->size; i++)
    {
        printf("Block %d: ", i);
        print_subblock_string(&(blocks->sub_blocks[i]));
    }
}

// Fonction pour afficher le contenu d'un sous-bloc en binaire
void print_subblock_binary(SubBlock *subblock)
{
    for (int i = 0; i < SUB_BLOCK_SIZE; i++)
    {
        for (int j = 7; j >= 0; j--)
        {
            printf("%d", (subblock->data[i] >> j) & 1);
        }
        printf(" "); // Ajouter un espace entre chaque octet
    }
}

// Fonction pour afficher le contenu des blocs en binaire
void print_blocks_binary(Block *blocks)
{
    for (int i = 0; i < blocks->size; i++)
    {
        printf("Block %d (binary): ", i);
        print_subblock_binary(&(blocks->sub_blocks[i]));
        printf("\n");
    }
}

// Fonction pour afficher le contenu d'un sous-bloc en hexadécimal
void print_subblock_hex(SubBlock *subblock)
{
    for (int i = 0; i < SUB_BLOCK_SIZE; i++)
    {
        printf("%02X ", subblock->data[i]);
    }
    printf("\n");
}

// Fonction pour afficher le contenu d'un bloc en hexadécimal
void print_blocks_hex(Block *blocks)
{
    for (int i = 0; i < blocks->size; i++)
    {
        printf("Block %d (hexadecimal): ", i);
        print_subblock_hex(&(blocks->sub_blocks[i]));
    }
}

// Fonction pour afficher l'expansion d'une clé en hexadécimal
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

// Fonction pour effectuer l'opération XOR entre un sous-bloc et une chaîne de caractères binaire
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
        char byte_string[3];                         // Stocke le byte en format texte (ex: "0A")
        strncpy(byte_string, &hex_string[i * 2], 2); // Extraire le byte hexadécimal
        byte_string[2] = '\0';                       // Terminer la chaîne de caractères

        unsigned int byte_value = (unsigned int)strtol(byte_string, NULL, SUB_BLOCK_SIZE); // Convertir le byte hexadécimal en entier
        subblock->data[i] ^= byte_value;                                                   // Effectuer l'opération XOR avec le sous-bloc
    }
}

// Fonction pour effectuer le XOR entre la clé et chaque sous-bloc du bloc
void xor_blocks_with_key(Block *blocks, const char *key)
{
    for (int i = 0; i < blocks->size; i++)
    {
        xor_subblock(&(blocks->sub_blocks[i]), key);
    }
}

// Fonction pour multiplier deux nombres dans le corps de Galois GF(2^8)
unsigned int multiply(unsigned int a, unsigned int b)
{
    unsigned int result = 0;
    unsigned int carry = 0;

    for (int i = 0; i < 8; i++)
    {
        if (b & 1)
        {
            result ^= a;
        }

        carry = a & 0x80; // Vérifier le bit le plus à gauche de a

        a <<= 1; // Décalage de a vers la gauche d'un bit

        if (carry)
        {
            a ^= 0x1B; // XOR avec le polynôme réducteur 0x11B (x^8 + x^4 + x^3 + x + 1)
        }

        b >>= 1; // Décalage de b vers la droite d'un bit
    }

    return result;
}