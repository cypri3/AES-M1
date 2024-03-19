#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "utils.h"
#include <ctype.h> // Bibliothèque de tests pour les clés

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