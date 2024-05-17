#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "utils.h"
#include "AES_fun.h"
#include "ECB.h"
#include "CFB.h"
#include "CBC.h"
#include "GCM.h"
#include "multi_threading.h"
#include <pthread.h>

#define MAX_KEY_SIZE 48 + 1 // Maximum length in bytes (or 256 bits plus the \0 which have to be considered in the C language)
#define SUB_BLOCK_SIZE 16
extern pthread_barrier_t barrier;

int verbose = 1; // 1 is to print in a terminal, which is the default mode and 0 is to only keep useful data (the others will be in a new file)

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
        printf("-e, --hexadecimal              read the input file in hexadecimal format (ie: 48656c6c6f2c2041455321...)\n");
        printf("-k KEY, --key KEY              set the encryption/decryption key in hexadecimal format\n");
        printf("-v KEY, --initvect KEY         set the initialization vector in hexadecimal format\n");
        printf("-a KEY, --authdata KEY         set the authentification data in hexadecimal format\n");
        printf("-i KEY, --increment KEY        set the increment value in hexadecimal format\n");
        printf("-t KEY, --tag KEY              set the validation tag in hexadecimal format\n");
        printf("-g SIZE, --generate SIZE       generate a random key of the specified size (128, 192, 256)\n");
        printf("-o FILE, --output FILE         specify the output file\n");
        printf("-b [FILE], --benchmark [FILE]  perform a benchmark with alice.txt or any file if given\n");
        printf("-c, --cipher                   perform encryption\n");
        printf("-d, --decipher                 perform decryption\n");
        printf("-h [N], --help [N]             display this help message\n");
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
        printf("./AES -e -b tests/hex_test_file.txt\n");
        printf("./AES -c -k 0x000102030405060708090a0b0c0d0e0f -o encrypted_file.txt original_file.txt\n");
        printf("./AES -d -k 0x000102030405060708090a0b0c0d0e0f -o decrypted_file.txt encrypted_file.txt\n");
        printf("./AES -e -m ECB -k 0x000102030405060708090a0b0c0d0e0f -o encrypted_file.txt input_hex.txt\n");
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

    int key_size = 128;                              // Key length in bits (128, 192 or 256)
    char key[MAX_KEY_SIZE];                          // Storage of the generated key
    strcpy(key, "000102030405060708090a0b0c0d0e0f"); // Default vector

    char IV[MAX_KEY_SIZE];
    strcpy(IV, "00000000000000000000000000000001"); // Default vector

    char auth_data[MAX_KEY_SIZE];
    strcpy(auth_data, "00000000000000000000000000000001"); // Default vector

    char inc[MAX_KEY_SIZE];
    strcpy(inc, "00000000000000000000000000000001"); // Default vector

    char tag[MAX_KEY_SIZE];
    strcpy(tag, "00000000000000000000000000000001"); // Default vector

    // Flags for options
    char *output_file = NULL;
    FILE *output;
    int mode_selected = 0;       // ECB CBC CFB GCM in int
    char *mode = 0;              // ECB CBC CFB GCM in char
    bool as_hexadecimal = false; // Flag to read an hexa text

    // Flags to determine the execution mode
    int is_solver = 2;
    bool is_benchmark = false;
    bool is_generator = NULL;

    // Organization to describ long options
    static struct option long_options[] = {
        {"mode", required_argument, 0, 'm'},
        {"hexadecimal", required_argument, 0, 'e'},
        {"key", required_argument, 0, 'k'},
        {"initvect", required_argument, 0, 'v'},
        {"authdata", required_argument, 0, 'a'},
        {"increment", required_argument, 0, 'i'},
        {"tag", required_argument, 0, 't'},
        {"generate", required_argument, 0, 'g'},
        {"output", required_argument, 0, 'o'},
        {"help", required_argument, 0, 'h'},
        {"benchmark", no_argument, 0, 'b'},
        {"cipher", no_argument, 0, 'c'},
        {"decipher", no_argument, 0, 'd'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long_only(argc, argv, "m:ek:v:a:i:t:g:o:h:bcd", long_options, &option_index)) != -1)
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
        case 'e': // Hexadecimal
            printf("Option -hex (hexadecimal) selected\n");
            as_hexadecimal = true;
            break;
        case 'k':
            printf("Option -k (key) with value: %s\n", optarg);
            if (strncmp(optarg, "0x", 2) == 0)
            {
                strcpy(key, optarg + 2); // Copy of the optarg without the two first characters ("0x")
            }
            else
            {
                strcpy(key, optarg); // Copy of the optarg as it is
            }

            if (!valid_key(key))
            {
                printf("Invalid key: %s\n", key);
                break;
            }
            key_size = strlen(key) * 4; // Definition of the key's length
            break;
        case 'v':
            printf("Option -i (initation vector) with value: %s\n", optarg);
            if (strncmp(optarg, "0x", 2) == 0)
            {
                strcpy(IV, optarg + 2); // Copy of the optarg without the two first characters ("0x")
            }
            else
            {
                strcpy(IV, optarg); // Copy of the optarg as it is
            }
            if (!valid_IV(IV))
            {
                printf("Invalid IV: %s\n", IV);
            }
            break;
        case 'a':
            if (strncmp(optarg, "0x", 2) == 0)
            {
                strcpy(auth_data, optarg + 2); // Copy of the optarg without the two first characters ("0x")
            }
            else
            {
                strcpy(auth_data, optarg); // Copy of the optarg as it is
            }
            if (!valid_auth_data(auth_data))
            {
                printf("Invalid auth_data: %s\n", optarg);
                printf("An hexadecimal auth_data is required.\n");
            }
            else
            {
                printf("Option -a (authentification tag) with value: %s\n", auth_data);
            }
            break;
        case 'i':
            if (strncmp(optarg, "0x", 2) == 0)
            {
                strcpy(inc, optarg + 2); // Copy of the optarg without the two first characters ("0x")
            }
            else
            {
                strcpy(inc, optarg); // Copy of the optarg as it is
            }
            if (!valid_auth_data(inc))
            {
                printf("Invalid inc: %s\n", optarg);
                printf("An hexadecimal incrementation vector is required.\n");
            }
            else
            {
                printf("Option -a (incrementation vector) with value: %s\n", inc);
            }
            break;
        case 't':
            if (strncmp(optarg, "0x", 2) == 0)
            {
                strcpy(tag, optarg + 2); // Copy of the optarg without the two first characters ("0x")
            }
            else
            {
                strcpy(tag, optarg); // Copy of the optarg as it is
            }
            if (!valid_auth_data(tag))
            {
                printf("Invalid tag: %s\n", optarg);
                printf("An hexadecimal validation tag is required.\n");
            }
            else
            {
                printf("Option -a (validation tag) with value: %s\n", tag);
            }
            break;
        case 'g': // Generation of key
            printf("Option -g (generate) with value: %s\n", optarg);
            int size = atoi(optarg);
            if (size == 128 || size == 192 || size == 256)
            {
                key_size = size;
            }
            else
            {
                printf("Invalid key size: %d\n128,192 or 256 needed.\n", size);
                exit(EXIT_FAILURE);
            }
            is_generator = true; // Set the generator mode flag
            break;
        case 'o':
            printf("Option -o (output) with value: %s\n", optarg);
            output_file = optarg;
            verbose = 0;
            break;
        case 'h': // Help
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

    // Raise a warning if the solver mode is on or if the solver mode is off but no file has been given
    if (!(optind < argc) && (is_solver != 2))
    {
        printf("No files given for ");
        if (is_solver == 0)
        {
            printf("encryption mode\n");
        }
        else
        {
            printf("decryption mode\n");
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

    if (is_generator)
    {
        // Initialize of random numbers generator
        srand(time(NULL));

        // Generate of the random key
        generate_random_key(key_size, key);

        // Print generated key
        printf("Generated key (in hexadecimal) : 0x");
        for (int i = 0; i < key_size / 8; i++)
        {
            printf("%02x", key[i] & 0xFF); // Print of each key's byte in hexadecimal
        }
        printf("\n");
    }

    if (is_benchmark)
    {
        for (int i = optind; (i < argc) || (i == argc); i++)
        {
            long int file_size;
            char *file_content;
            if (i == argc)
            {
                file_content = read_file("tests/alice.txt", &file_size, false);
                printf("ALICE ////\n");
            }
            else
            {
                file_content = read_file(argv[i], &file_size, as_hexadecimal);
            }
            // Convert the text in blocks
            Block *blocks = text_to_blocks(file_content, file_size);

            // Create round keys
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

            if (verbose)
            {
                printf("key size : %d\n", key_size);
            }
            KeyExpansion(key, key_size, expanded_key, Nr);

            // Create the super-structure with the copies of the blocks
            SuperBlock *super_block = create_superblock_with_copies(blocks, 100);
            if (super_block == NULL)
            {
                fprintf(stderr, "Failed to create the superblock.\n");
                return EXIT_FAILURE;
            }

            // Initialize the barrier
            pthread_barrier_init(&barrier, NULL, super_block->num_blocks);

            // Create the threads
            pthread_t threads[super_block->num_blocks];

            struct timespec start, end;
            double elapsed_time;

            // Start timer
            clock_gettime(CLOCK_REALTIME, &start);

            for (int i = 0; i < super_block->num_blocks; i++)
            {
                // Create the arguments for the thread
                ThreadArgs *thread_args = malloc(sizeof(ThreadArgs));
                if (thread_args == NULL)
                {
                    fprintf(stderr, "Memory allocation error.\n");
                    // Clean the ressources and quit
                    pthread_barrier_destroy(&barrier);
                    free_superblock(super_block);
                    return EXIT_FAILURE;
                }
                thread_args->block = &(super_block->blocks[i]);
                thread_args->expanded_key = malloc(expanded_key_size * sizeof(unsigned char));
                if (thread_args->expanded_key == NULL)
                {
                    fprintf(stderr, "Memory allocation error.\n");
                    free(thread_args);
                    // Clean the ressources and quit
                    pthread_barrier_destroy(&barrier);
                    free_superblock(super_block);
                    return EXIT_FAILURE;
                }
                memcpy(thread_args->expanded_key, expanded_key, expanded_key_size);
                thread_args->Nr = malloc(sizeof(int));
                if (thread_args->Nr == NULL)
                {
                    fprintf(stderr, "Memory allocation error.\n");
                    free(thread_args->expanded_key);
                    free(thread_args);
                    // Clean the ressources and quit
                    pthread_barrier_destroy(&barrier);
                    free_superblock(super_block);
                    return EXIT_FAILURE;
                }
                *(thread_args->Nr) = Nr;

                // Create the thread and execute the thread founction
                if (pthread_create(&threads[i], NULL, process_blocks_ECB, thread_args) != 0)
                {
                    fprintf(stderr, "Error creating thread %d\n", i);
                    // Clean the ressources and quit
                    pthread_barrier_destroy(&barrier);
                    free_superblock(super_block);
                    return EXIT_FAILURE;
                }
                // printf("Launching thread n°%d\n", i); //If needed
            }

            // Wait for all the threads to be finished
            for (int j = 0; j < super_block->num_blocks; j++)
            {
                pthread_join(threads[j], NULL);
            }

            // Stop timer
            clock_gettime(CLOCK_REALTIME, &end);

            // Compute elapsed time
            elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

            free_superblock(super_block);

            // Destroy the barrier
            pthread_barrier_destroy(&barrier);

            free_block(blocks);
            free(file_content); // Free the allocated memory for the content of the file
            // Display the elapsed time
            if (i == argc)
            {
                printf("Elapsed time for ciphering the file 'tests/alice.txt' 100 times: %f seconds\n", elapsed_time);
            }
            else
            {
                printf("Elapsed time for ciphering the file '%s' 100 times: %f seconds\n", argv[i], elapsed_time);
                if (i == argc - 1)
                {
                    exit(EXIT_SUCCESS);
                }
            }
        }
        exit(EXIT_SUCCESS);
    }

    // Read the content of the specified file in argument
    for (int i = optind; i < argc; i++)
    {
        SubBlock TAG_subblock;

        if (verbose)
        {
            printf("Reading file: %s\n", argv[i]);
        }
        long int file_size;
        char *file_content = read_file(argv[i], &file_size, as_hexadecimal);
        if (verbose)
        {
            printf("File content:\n%s\n", file_content);
        }

        // Convert the text in blocks
        Block *blocks = text_to_blocks(file_content, file_size);

        // Create round keys
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

        if (verbose)
        {
            printf("key size : %d\n", key_size);
        }
        KeyExpansion(key, key_size, expanded_key, Nr);
        // Print of the expansion key
        // print_expanded_key_hex(expanded_key_size, expanded_key); // TODO mettre un mode verbose ?

        if (is_solver != 1)
        {
            if (verbose)
            {
                printf("\nEncryption mode\n");
            }

            if (mode_selected == 0)
            {
                // ECB
                AESEncryptionECB(blocks, expanded_key, Nr);
            }
            else if (mode_selected == 1)
            {
                // CBC
                AESEncryptionCBC(blocks, IV, expanded_key, Nr);
            }
            else if (mode_selected == 2)
            {
                // CFB
                AESEncryptionCFB(blocks, IV, expanded_key, Nr);
            }
            else
            {
                // GCM
                TAG_subblock = AESEncryptionGCM(blocks, IV, inc, auth_data, expanded_key, Nr);
            }
            // Print the blocks into a text format
            if (verbose)
            {
                printf("Text as string blocks \n");
            }
            print_blocks_string(blocks);

            if (output_file == NULL)
            {
                // Print of blocks into a binary format
                if (verbose)
                {
                    printf("Text as binary blocks \n");
                }
                print_blocks_binary(blocks);

                // Print of blocks into an hexadecimal format
                if (verbose)
                {
                    printf("Text as hex blocks \n");
                }
                print_blocks_hex(blocks);
                if (mode_selected == 3)
                {
                    printf("The authentication tag is:\n");
                    print_subblock_hex(&TAG_subblock);
                }
            }
        }
        if (is_solver != 0)
        {
            if (verbose)
            {
                printf("\nDecryption mode\n");
            }

            if (mode_selected == 0)
            {
                // ECB
                AESDecryptionECB(blocks, expanded_key, Nr);

                // Print the blocks into a text format
                if (verbose)
                {
                    printf("Text as string blocks \n");
                }
                print_blocks_string(blocks);
            }
            else if (mode_selected == 1)
            {
                // CBC
                AESDecryptionCBC(blocks, IV, expanded_key, Nr);
                if (verbose)
                {
                    printf("Text as string blocks \n");
                }
                print_blocks_string(blocks);
            }
            else if (mode_selected == 2)
            {
                // CFB
                AESDecryptionCFB(blocks, IV, expanded_key, Nr);
                if (verbose)
                {
                    printf("Text as string blocks \n");
                }
                print_blocks_string(blocks);
            }
            else
            {
                // GCM
                if (TAG_subblock.data == NULL)
                {
                    TAG_subblock = *create_subblock();
                    if (!set_subblock_with_hex(&(TAG_subblock), tag))
                    {
                        printf("Failed to set subblock data.\n");
                    }
                }
                AESDecryptionGCM(blocks, IV, inc, auth_data, expanded_key, Nr, &(TAG_subblock));
                // Print the blocks into a text format
                if (verbose)
                {
                    printf("Text as string blocks \n");
                }
                print_blocks_string(blocks);
            }
        }
        free_block(blocks);
        free(file_content); // Free the allocated memory for the content in the file
    }

    return 0;
}
