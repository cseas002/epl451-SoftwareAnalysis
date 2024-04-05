#include "elf_mdb_helpers.h"

Elf_Scn *getSymbolTable(Elf *elf)
{
    /* Loop over sections.  */
    Elf_Scn *scn = NULL; // Discriptor for ELF file section
    GElf_Shdr shdr;      // Section Header data type
    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) // Get section header string index, and save it shstrndx
        DIE("(getshdrstrndx) %s", elf_errmsg(-1));

    while ((scn = elf_nextscn(elf, scn)) != NULL) // Loop over the sections, and save them in scn
    {
        if (gelf_getshdr(scn, &shdr) != &shdr) // Get the section header and save it in shdr
            DIE("(getshdr) %s", elf_errmsg(-1));

        if (shdr.sh_type == SHT_SYMTAB) // If you found the symbol table, return it
            return scn;
    }

    // If no symbol table is found, return NULL
    return NULL;
}

long getSymbolAddress(char *symbol, Elf *elf, Elf_Scn *symtab)
{
    Elf_Data *data;
    GElf_Shdr shdr;
    int count = 0;

    /* Get the descriptor.  */
    if (gelf_getshdr(symtab, &shdr) != &shdr)
        DIE("(getshdr) %s", elf_errmsg(-1));

    data = elf_getdata(symtab, NULL);
    count = shdr.sh_size / shdr.sh_entsize; // Find how many symbols there are

    // For each symbol, print its details
    for (int i = 0; i < count; ++i)
    {
        GElf_Sym sym;
        gelf_getsym(data, i, &sym);
        // If the symbol name is the symbol I'm searching, then get return the address
        if (!strcmp(elf_strptr(elf, shdr.sh_link, sym.st_name), symbol))
            return sym.st_value;
    }

    return 0;
}