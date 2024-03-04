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

void disas(csh handle, const unsigned char *buffer, unsigned int size)
{
    cs_insn *insn;
    size_t count;

    printf("Size: %d\n", size);
    count = cs_disasm(handle, buffer, size, 0x0, 0, &insn);

    printf("Instructions: %ld\n", count);
    if (count > 0)
    {
        size_t j;
        for (j = 0; j < count; j++)
        {
            printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
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
    count = shdr.sh_size / shdr.sh_entsize;

    for (int i = 0; i < 100; i++)
        printf("-");
    printf("\n\nPrinting symbol table:\n\n");
    printf("%-5s %-16s %-6s %-5s %s\n", "[  Nr]", "Value", "Type", "Bind", "Name");
    for (int i = 0; i < count; ++i)
    {
        GElf_Sym sym;
        gelf_getsym(data, i, &sym);
        if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC || ELF64_ST_TYPE(sym.st_info) == STT_OBJECT)
            printf("[%4d] %-16lx %-6s %-5s %s\n", i, sym.st_value, get_symbol_type(sym.st_info), get_symbol_binding(sym.st_info), elf_strptr(elf, shdr.sh_link, sym.st_name));
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
           "Type", "Address", "Offset", "Size", "Flags");

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
            // printf("%ld", shdr.sh_flags);
            // printf("%s\n", flag_names);

            printf("\n[%2d] %-20s %-16s %-16lx %-16lx %-16lx %-4s\n", s_index++,
                   elf_strptr(elf, shstrndx, shdr.sh_name),
                   get_section_type(shdr.sh_type), shdr.sh_addr, shdr.sh_offset, shdr.sh_size, flag_names);

            // Disassembly
            Elf_Data *data = NULL;
            size_t n = 0;

            data = elf_getdata(scn, data);
            // printf("Size of data: %ld\n", data->d_size);
            disas(handle, data->d_buf, data->d_size);
        }
        /* Locate symbol table.  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab")) // strcmp returns 0 if it finds ".symtab", so it will enter if it finds it
            symtab = scn;
    }

    print_symbol_table(elf, symtab);
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
