#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "utils.h"

#define MAX_KEY_SIZE 32 + 1 // Taille maximale en octets (256 bits + \0 qui doit être pris en compte pour le C)

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
        printf("./AES -m ECB -k 0x2b7e151628aed2a6abf7158809cf4f3c -o encrypted_file.txt original_file.txt\n");
        printf("./AES -m CBC -k 0x2b7e151628aed2a6abf7158809cf4f3c -o encrypted_file.txt original_file.txt\n");
        printf("./AES -m CFB -k 0x2b7e151628aed2a6abf7158809cf4f3c -o encrypted_file.txt original_file.txt\n");
        printf("./AES -m GCM -k 0x2b7e151628aed2a6abf7158809cf4f3c -o encrypted_file.txt original_file.txt\n");
        printf("./AES -g 256 -o generated_key.txt\n");
        printf("./AES -b\n");
        printf("./AES -c -k 0x2b7e151628aed2a6abf7158809cf4f3c -o encrypted_file.txt original_file.txt\n");
        printf("./AES -d -k 0x2b7e151628aed2a6abf7158809cf4f3c -o decrypted_file.txt encrypted_file.txt\n");
        printf("\nFor more options, try ./AES -h 1\n\n");
    }
    else
    {
        printf("Invalid help page number.\n");
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
                key_size = strlen(key) - 2;
            }
            else
            {
                strcpy(key, optarg); // Copier optarg tel quel
                key_size = strlen(key);
            }
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

    if (is_solver == 1)
    {
        // Lire le contenu du fichier spécifié en argument
        for (int i = optind; i < argc; i++)
        {
            printf("Reading file: %s\n", argv[i]);
            char *file_content = read_file(argv[i]);
            printf("File content:\n%s\n", file_content);
            free(file_content); // Libérer la mémoire allouée
        }
        printf("Decryption mode\n");
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
