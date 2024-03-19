#ifndef UTILS_H
#define UTILS_H

typedef struct
{
    int size;     // Grid size (e.g., 16 for a 16x16 grid)
    char **cells; // Two-dimensional array to store cell contents
} u_grid;

int validate_key(const char *key);
void generate_random_key(int key_size, char *key);
char *read_file(const char *filename);
#endif /* UTILS_H */