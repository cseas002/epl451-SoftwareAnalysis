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

// This is from readelf.c (https://github.com/bminor/binutils-gdb/blob/8bbce0c70250334f436b4e52983f3538d3bdb9ce/binutils/readelf.c#L5931)
// const char *get_flags_names(unsigned long flags)
// {
//     // Define some common ELF section flags
//     static const struct
//     {
//         unsigned long flag;
//         const char *name;
//     } flag_mapping[] = {
//         {SHF_WRITE, "W"},
//         {SHF_ALLOC, "A"},
//         {SHF_EXECINSTR, "X"},
//         {SHF_MERGE, "M"},
//         {SHF_STRINGS, "S"},
//         {SHF_INFO_LINK, "I"},
//         {SHF_LINK_ORDER, "L"},
//         {SHF_OS_NONCONFORMING, "O"},
//         {SHF_GROUP, "G"},
//         {SHF_TLS, "T"},
//         {SHF_EXCLUDE, "E"},
//         {SHF_COMPRESSED, "C"}};

//     // Allocate a buffer for storing flag names
//     char *flag_names = malloc(strlen("RWX") + 1);
//     if (!flag_names)
//         DIE("Memory allocation failed");

//     // Initialize the buffer
//     flag_names[0] = '\0';

//     // Check each flag and append its name to the buffer if present
//     for (size_t i = 0; i < sizeof(flag_mapping) / sizeof(flag_mapping[0]); ++i)
//     {
//         if (flags & flag_mapping[i].flag)
//             strcat(flag_names, flag_mapping[i].name);
//     }

//     return flag_names;
// }

const char *get_symbol_type(unsigned char st_info)
{
    // Even if only the STT_FUNC is used, this function returns the appropriate type
    switch (ELF64_ST_TYPE(st_info))
    {
    case STT_NOTYPE:
        return "NOTYPE";
    case STT_OBJECT:
        return "OBJECT";
    case STT_FUNC:
        return "FUNCTION";
    case STT_SECTION:
        return "SECTION";
    case STT_FILE:
        return "FILE";
    case STT_COMMON:
        return "COMMON";
    case STT_TLS:
        return "TLS";
    default:
        return "UNKNOWN";
    }
}

const char *get_symbol_binding(unsigned char st_info)
{
    switch (ELF64_ST_BIND(st_info))
    {
    case STB_LOCAL:
        return "LOCAL";
    case STB_GLOBAL:
        return "GLOBAL";
    case STB_WEAK:
        return "WEAK";
    case STB_GNU_UNIQUE:
        return "GNU_UNIQUE";
    default:
        return "UNKNOWN";
    }
}

const char *get_section_type(unsigned int sh_type)
{
    switch (sh_type)
    {
    case SHT_NULL:
        return "NULL";
    case SHT_PROGBITS:
        return "PROGBITS";
    case SHT_SYMTAB:
        return "SYMTAB";
    case SHT_STRTAB:
        return "STRTAB";
    case SHT_RELA:
        return "RELA";
    case SHT_HASH:
        return "HASH";
    case SHT_DYNAMIC:
        return "DYNAMIC";
    case SHT_NOTE:
        return "NOTE";
    case SHT_NOBITS:
        return "NOBITS";
    case SHT_REL:
        return "REL";
    case SHT_SHLIB:
        return "SHLIB";
    case SHT_DYNSYM:
        return "DYNSYM";
    default:
        return "UNKNOWN";
    }
}