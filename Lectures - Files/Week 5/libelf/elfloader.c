#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libelf.h>
#include <gelf.h>


#define DIE(...) \
    do { \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)


void print_symbol_table(Elf *elf, Elf_Scn *scn) {
    Elf_Data *data;
    GElf_Shdr shdr;
    int count = 0;

    /* Get the descriptor.  */
    if (gelf_getshdr(scn, &shdr) != &shdr)
        DIE("(getshdr) %s", elf_errmsg(-1));

    data = elf_getdata(scn, NULL);
    count = shdr.sh_size / shdr.sh_entsize;

    fprintf(stderr, "Printing symbol table.\n");
    for (int i = 0; i < count; ++i) {
        GElf_Sym sym;
        gelf_getsym(data, i, &sym);
        if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC || ELF64_ST_TYPE(sym.st_info) == STT_OBJECT)
            fprintf(stderr, "%016lx %x %s\n", sym.st_value, sym.st_info, elf_strptr(elf, shdr.sh_link, sym.st_name));
    }
}

void load_file(char *filename) {

    Elf *elf;
    Elf_Scn *symtab;    /* To be used for printing the symbol table.  */

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

    int s_index = 0;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            DIE("(getshdr) %s", elf_errmsg(-1));

        fprintf(stderr, "[%2d] %-20s %4d %016lx %06lx %06lx\n", s_index++, 
            elf_strptr(elf, shstrndx, shdr.sh_name), 
            shdr.sh_type, shdr.sh_addr, shdr.sh_offset, shdr.sh_size);

        /* Locate symbol table.  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab")) 
            symtab = scn;
    }

    print_symbol_table(elf, symtab);
}

int main(int argc, char *argv[]) {

    if (argc < 2) 
        DIE("usage: elfloader <filename>");
    
    load_file(argv[1]);

    return 1;
}
