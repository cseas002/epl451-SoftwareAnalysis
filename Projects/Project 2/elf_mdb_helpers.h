// elf_helpers.h

#ifndef ELF_MDB_HELPERS_H
#define ELF_MDB_HELPERS_H

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <capstone/capstone.h>

#define DIE(...)                      \
    do                                \
    {                                 \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr);          \
        exit(EXIT_FAILURE);           \
    } while (0)

// Function to get ELF section flags as a string
const char *get_flags_names(unsigned long flags);

// Function to get human-readable symbol type
const char *get_symbol_type(unsigned char st_info);

// Function to get human-readable symbol binding
const char *get_symbol_binding(unsigned char st_info);

// Function to get human-readable section type
const char *get_section_type(unsigned int sh_type);

// Function to get the symbol address
long getSymbolAddress(char *symbol, Elf *elf, Elf_Scn *symtab);

// Function to get symbol table
Elf_Scn *getSymbolTable(Elf *elf);

#endif // ELF_HELPERS_H
