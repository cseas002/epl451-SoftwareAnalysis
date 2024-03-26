#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libelf.h>
#include <gelf.h>
#include "elf_helpers.h"
#include <capstone/capstone.h>

void disas(csh handle, const unsigned char *buffer, unsigned int size, uint64_t start_address)
{
    cs_insn *insn;
    size_t count;

    printf("Size: %d\n", size);
    count = cs_disasm(handle, buffer, size, start_address, 0, &insn);

    printf("Instructions: %ld\n", count);
    if (count > 0)
    {
        size_t j;
        for (j = 0; j < count; j++)
        {
            printf("0x%08lx:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                   insn[j].op_str);
        }
        cs_free(insn, count);
    }
    else
        fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
}

void print_symbol_table(Elf *elf, Elf_Scn *scn)
{
    Elf_Data *data;
    GElf_Shdr shdr;
    int count = 0;

    /* Get the descriptor.  */
    if (gelf_getshdr(scn, &shdr) != &shdr)
        DIE("(getshdr) %s", elf_errmsg(-1));

    data = elf_getdata(scn, NULL);
    count = shdr.sh_size / shdr.sh_entsize; // Find how many symbols there are

    // Print - just for distinguish purposes
    for (int i = 0; i < 100; i++)
        printf("-");
    printf("\n\nPrinting symbol table:\n\n");
    printf("%-5s %-16s %-16s %-16s %s\n", "[  Nr]", "Value", "Type", "Bind", "Name"); // Print the header
    // For each symbol, print its details
    for (int i = 0; i < count; ++i)
    {
        GElf_Sym sym;
        gelf_getsym(data, i, &sym);
        // If the symbol type is a function, then print it. I used helper functions to print the names instead of the numbers
        if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC)
            printf("[%4d] 0x%014lx %-16s %-16s %s\n", i, sym.st_value, get_symbol_type(sym.st_info), get_symbol_binding(sym.st_info), elf_strptr(elf, shdr.sh_link, sym.st_name));
    }
}

void print_details(char *filename, csh handle)
{
    Elf *elf;
    Elf_Scn *symtab; /* To be used for printing the symbol table.  */

    /* Initilization.  */
    if (elf_version(EV_CURRENT) == EV_NONE)
        DIE("(version) %s", elf_errmsg(-1));

    int fd = open(filename, O_RDONLY);

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        DIE("(begin) %s", elf_errmsg(-1));

    /* Loop over sections.  */
    Elf_Scn *scn = NULL; // Discriptor for ELF file section
    GElf_Shdr shdr;      // Section Header data type
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) // Get section header string index, and save it shstrndx
        DIE("(getshdrstrndx) %s", elf_errmsg(-1));

    printf("[Nr] %-20s %-16s %-16s %-16s %-16s %-16s\n",
           "Name",
           "Type", "Address", "Offset", "Size", "Flags"); // Print the header

    int s_index = 0;
    while ((scn = elf_nextscn(elf, scn)) != NULL) // Loop over the sections, and save them in scn
    {
        if (gelf_getshdr(scn, &shdr) != &shdr) // Get the section header and save it in shdr
            DIE("(getshdr) %s", elf_errmsg(-1));

        // We want to print only the executables, so let's check the flag. There should be an X flag, which is number 4 (SHF_EXECISTR)
        if (shdr.sh_flags & SHF_EXECINSTR) // if it has flag "X" (executable), then print it
        {
            // Use the function to get flag names
            const char *flag_names = get_flags_names(shdr.sh_flags);

            printf("\n[%2d] %-20s %-16s 0x%014lx 0x%-14lx %-16lx %-4s\n", s_index++,
                   elf_strptr(elf, shstrndx, shdr.sh_name),
                   get_section_type(shdr.sh_type), shdr.sh_addr, shdr.sh_offset, shdr.sh_size, flag_names); // Print the header

            // Disassembly
            Elf_Data *data = NULL;
            size_t n = 0;

            data = elf_getdata(scn, data);
            disas(handle, data->d_buf, data->d_size, shdr.sh_addr);
        }

        /* Locate symbol table.  */
        // We can either locate the .symtab section, or find the section that has sh_type SHT_SYMTAB (0x2)
        // The user can alter the name of the symtab section, so the best way to do it the second one

        // OLD IMPLEMENTATION:
        // if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab")) // strcmp returns 0 if it finds ".symtab", so it will enter if it finds it
        //     symtab = scn;                                                // Save the section where the symbol table is, so we can print it at the end

        // NEW SHT_SYMTAB IMPLEMENTATION:
        if (shdr.sh_type == SHT_SYMTAB)
            symtab = scn;
    }

    print_symbol_table(elf, symtab); // Print the symbol table
}

int main(int argc, char *argv[])
{
    if (argc < 2)
        DIE("usage: elfloader <filename>");

    /* Initialize the engine.  */
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;

    /* AT&T */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    print_details(argv[1], handle);

    cs_close(&handle);

    return 1;
}
