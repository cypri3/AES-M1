# 🚨 Educational Project Notice 🚨

**This project is for educational purposes only. It is not intended for use in real-world cryptographic applications. Do not use this implementation for securing sensitive data.**

---

# AES-M1

## AES Implementation Project for Cryptography Course

This project entails the comprehensive implementation of the Advanced Encryption Standard (AES) in the C programming language. Guided by course material and standard documentation, the project begins with a thorough understanding of the AES standard (FIPS-197), developing functional encryption and decryption algorithms for single-block processing using 128-bit keys. Subsequent stages expand functionality to support various text and key sizes, along with implementing multiple modes of operation such as ECB, CBC, CFB, OFB, and GCM, adaptable to key sizes of 128, 192, or 256 bits as selected by the user. Emphasis is placed on clear documentation, code readability, and addressing encountered challenges through the accompanying report, which includes user instructions, testing scripts, implementation insights, and solutions to overcome hurdles faced during development.

## Table of Contents

1. [Introduction](#introduction)
2. [Usage Guide](#usage-guide)
   - [Downloading and Compiling](#downloading-and-compiling)
   - [User Instructions](#user-instructions)
3. [Test Program](#test-program)
4. [Implementation Details](#implementation-details)
5. [Challenges and Solutions](#challenges-and-solutions)
6. [Conclusion](#conclusion)

## Introduction

### Project Overview

This project aims to develop a robust and optimized implementation of the AES (Advanced Encryption Standard) symmetric encryption algorithm, widely used to secure digital data. The primary goal is to provide a high-performance version of AES supporting encryption and decryption of files efficiently and securely, integrating multiple AES modes of operation: ECB, CBC, CFB, and GCM. Special focus is given to optimizing the ECB mode for performance evaluation.

### Context

Developed in an academic setting, this AES project serves learning and research purposes. While rigorous, it may contain imperfections or bugs due to its experimental nature. The development was a collaborative effort, enhancing our understanding and skills in version control systems like Git, which was essential for coordinating work, tracking changes, and maintaining project organization.

## Usage Guide

### Downloading and Compiling

To use the AES project, download the source files and compile the program using the following steps:

#### Downloading the Source Code

```sh
git clone https://github.com/cypri3/AES-M1.git
```

#### Compiling the Project & Cleaning Compiled Files

Ensure GCC is installed on your system. Compile the project by running the following command in the project's root directory:
```sh
make all
```
This command will compile all necessary source files and generate the AES binary. To clean your working directory by removing all object files and the generated binary, use:
```sh
make clean
```
#### Getting Help

To display help information about available Makefile targets, use:
```sh
make help
```

### User Instructions

The AES program allows encrypting and decrypting files using various encryption modes (ECB, CBC, CFB, GCM) with a user-specified key. Here’s how to use different functionalities:

#### Encryption and Decryption

Example commands for encryption and decryption using different AES modes:
```sh
./AES -m ECB original.txt
./AES -m CBC original.txt
./AES -m CFB original.txt
./AES -m GCM original.txt
```

Commands with output files:
```sh
./AES -c -o encrypted.txt original.txt
./AES -d -o decrypted.txt encrypted.txt

```

For batch processing multiple texts:
```sh
./AES original1.txt original2.txt
```

#### Generating a Random Key

Generate a random key of the desired size (128, 192, 256 bits) and save it to a file:
```sh
./AES -g 256 -o generated_key.txt
```

Use generated keys as follows:
```sh
./AES -k 0x000102030405060708090a0b0c0d0e0f original.txt
```

#### Exporting to a File

Specify an output file for encryption or decryption results:
```sh
./AES -g 128 -m ECB -o encrypted.txt original.txt
```

#### Benchmarking

To evaluate encryption performance over 100 iterations:
```sh
./AES -b
```

Run a benchmark on a specific file:
```sh
./AES -b anotherfile.txt
```

#### Additional Options

- **Hexadecimal Input**: For reading the input file in hexadecimal format:
  ```sh
  ./AES -e -m ECB -k 0x000102030405060708090a0b0c0d0e0f -o out.txt in.txt
  ```
- **Initialization Vector**: Specify an initialization vector for modes like CBC, CFB, and GCM:
  ```sh
  ./AES -m CBC -i 0x00000000000000000000000000000001 -o out.txt in.txt
  ```
- **Authentication Data, Tag, and Increment**: For GCM mode, specify authentication data, a validation tag, and an increment value:
  ```sh
  ./AES -m GCM -a 0x00000000000000000000000000000001 -t 0x0a0b0c0d0e -i 0x01 -o out.txt in.txt
  ```

### Summary of Options

| Option              | Description                                              |
|---------------------|----------------------------------------------------------|
| `-m, --mode MODE`   | Set the mode of operation (ECB, CBC, CFB, GCM)           |
| `-e, --hexadecimal` | Read the input file in hexadecimal format                |
| `-k, --key KEY`     | Set the encryption/decryption key in hexadecimal format  |
| `-v, --initvect KEY`| Set the initialization vector in hexadecimal format      |
| `-a, --authdata KEY`| Set the authentication data in hexadecimal format        |
| `-i, --increment KEY`| Set the increment value in hexadecimal format           |
| `-t, --tag KEY`     | Set the validation tag in hexadecimal format             |
| `-g, --generate SIZE`| Generate a random key of specified size (128, 192, 256 bits) |
| `-o, --output FILE` | Specify the output file                                  |
| `-b, --benchmark [FILE]`| Perform a benchmark with `alice.txt` or any specified file |
| `-c, --cipher`      | Perform encryption                                       |
| `-d, --decipher`    | Perform decryption                                       |
| `-h, --help [N]`    | Display help messages                                    |

## Test Program

### Description of the Test Program

The test program measures AES encryption performance using the ECB mode on various files, including a predefined test file `alice.txt`. The test repeats the encryption process 100 times to obtain reliable performance metrics.

### Results and Interpretation

The benchmarking results on `alice.txt` show that the average time required to encrypt this file 100 times is approximately 0.81 seconds, indicative of the AES implementation's performance in a multithreaded environment.

## Implementation Details

### Code Structure and Modules

The project features a clear and modular code structure:

- **Main File: AES.c**: Entry point for the program, orchestrating the flow of encryption and decryption operations.
- **Utility Module: utils.c and utils.h**: Contains reusable utility functions and essential data structures (`Block`, `SubBlock`, and `SuperBlock`).
- **AES Functions Module: AES_fun.c**: Contains AES-specific functions, including basic encryption operations and transformations.
- **Encryption Modes Modules**: Each encryption mode (ECB, CBC, CFB, GCM) has its own source file.
- **Multithreading: multi_threading.c and multi_threading.h**: Implements multithreading functionalities to leverage modern processors' parallelization capabilities.

### Main Functions

- **AES Subfunctions**
- **AES Main Functions**
- **Encryption Modes**
- **Memory Allocation**
- **Multiplication Operations**

### Implementation Particularities

- **Use of Structures**: Enhances code readability and maintenance by organizing data into structures.
- **Time-Memory Tradeoff**: Prioritizes execution speed at the cost of increased memory usage.
- **Multithreading**: Implemented at a high level to handle multiple encryption operations in parallel.
- **Code Readability and Documentation**: Emphasis on clear, readable code with comprehensive documentation.
- **Key Generation**: Utilizes `stdlib.h` for generating keys based on the system time, suitable for testing.
- **Variety of Options**: Offers extensive configuration options to control various execution aspects.

## Challenges and Solutions

### Technical Obstacles and Solutions

- **Mathematical Problems**: Addressed using tests based on other implementations and the FIPS-197 standard.
- **Execution Time**: Improved by precomputing tables and adopting multithreading.
- **Memory Management**: Organized code and sequential task processing to optimize memory usage.
- **Project Organization**: Effective task distribution, version control, and clear objectives ensured project coherence.

## Conclusion

### Summary

The project successfully implemented AES encryption in an academic context, emphasizing a clear and modular code structure, performance optimization via multithreading and precomputed tables, and adaptability to various testing environments. Well-defined data structures and comprehensive documentation facilitate understanding and future extensions.

### Future Improvements

Potential enhancements include GPU acceleration, support for multiple file formats, advanced export options, comprehensive benchmarking, and improved user interfaces, both graphical and web-based, while ensuring security and validation of new features.