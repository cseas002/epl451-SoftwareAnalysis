#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <string.h>

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

void disas(csh handle, const unsigned char *buffer, unsigned int size)
{
    cs_insn *insn;
    size_t count;

    printf("%d\n", size);
    count = cs_disasm(handle, buffer, size, 0x0, 0, &insn);

    printf("%ld\n", count);
    if (count > 0)
    {
        size_t j;
        for (j = 0; j < count; j++)
        {
            fprintf(stderr, "0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                    insn[j].op_str);
        }
        cs_free(insn, count);
    }
    else
        fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
}

void disas_file(char *filename, csh handle)
{
    Elf *elf;

    /* Initilization.  */
    if (elf_version(EV_CURRENT) == EV_NONE)
        DIE("(version) %s", elf_errmsg(-1));

    int fd = open(filename, O_RDONLY);

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        DIE("(begin) %s", elf_errmsg(-1));

    /* Loop over sections.  */
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        DIE("(getshdrstrndx) %s", elf_errmsg(-1));

    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            DIE("(getshdr) %s", elf_errmsg(-1));

        /* Disassemble only executable sections */
        if ((shdr.sh_flags & SHF_EXECINSTR) && (shdr.sh_type == SHT_PROGBITS))
        {
            Elf_Data *data = NULL;
            size_t n = 0;

            // while (n < shdr.sh_size && (data = elf_getdata(scn, data)) != NULL) {
            data = elf_getdata(scn, data);
            printf("Disassembling section: %s\n", elf_strptr(elf, shstrndx, shdr.sh_name));

            disas(handle, data->d_buf, data->d_size);
            // }
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
        DIE("usage: elfloader <filename>");

    /* Initialize the disassembler. */
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        DIE("Failed to initialize disassembler");

    /* Set disassembler options. */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    /* Disassemble the file. */
    disas_file(argv[1], handle);

    /* Close the disassembler. */
    cs_close(&handle);

    return 0;
}