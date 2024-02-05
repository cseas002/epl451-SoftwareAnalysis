#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bfd.h>

#define DIE(...) \
    do { \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

unsigned int find_section(bfd * target, const char * section_name) {

    asection * bfd_sec;

    for (bfd_sec = target->sections; bfd_sec; bfd_sec = bfd_sec->next) {
        if (!strcmp(bfd_sec->name, section_name))
            return 1;
    }

    return 0;
}

void render_interpreter(bfd * target) {
    /* If it is a dynamically linked executable 
       print the interepreter.  */
    asection * bfd_sec, * interp_section = NULL;

    for (bfd_sec = target->sections; bfd_sec; bfd_sec = bfd_sec->next) {
        if (!strcmp(bfd_sec->name, ".interp"))
            interp_section = bfd_sec;
    }

    int size = bfd_section_size(target, interp_section);
    char *interpreter = malloc(size);
    bfd_get_section_contents(target, interp_section, interpreter, 0, size);
    fprintf(stderr, "interpreter: %s\n", interpreter);

    free(interpreter);
}


void render(bfd * target) {
    fprintf(stderr, "filename: %s\n", target->filename);
    fprintf(stderr, "flavour: %d\n", target->xvec->flavour);
    fprintf(stderr, "endianess: %d\n", target->xvec->byteorder);

    const bfd_arch_info_type *bfd_info = bfd_get_arch_info(target);
    fprintf(stderr, "architecture: %s\n", bfd_info->printable_name);

    /* Check version (program header).  */

    /* Check if dynamic (section .interp should exist).  */
    if (find_section(target, ".interp")) {
        fprintf(stderr, "linkage: dynamic\n");
        render_interpreter(target);
    } else
        fprintf(stderr, "linkage: static\n");


    /* Print the interepreter (the conents of the section .interp).  */

    /* Check if the binary is stripped (no .symtab section).  
       Will not work with libbfd, because not sections are displayed (obsolete API).
       You can verify this with: objdump -h
       Solution: attempt to parse the symbol table. If symbols are 0 then the
       binary is stripped. 
    */
    long n = bfd_get_dynamic_symtab_upper_bound(target);
    asymbol **bfd_symtab = malloc(n);
    long nsyms = bfd_canonicalize_symtab(target, bfd_symtab);
    if (nsyms == 0) {
        fprintf(stderr, "debug symbols: stripped\n");
    } else
        fprintf(stderr, "debug symbols: not stripped\n");

    free(bfd_symtab);
}

void load_file(char *filename) {

    bfd *bfd_h = NULL;
    
    bfd_init();

    bfd_h = bfd_openr(filename, NULL);
    if (!bfd_h)
        DIE("(openr) (%s)", bfd_errmsg(bfd_get_error()));

    /* Is it a binary object?  */
    if (!bfd_check_format(bfd_h, bfd_object))
        DIE("(check_format) (%s)", bfd_errmsg(bfd_get_error()));

    /* Do we know how to read this?  */
    if (bfd_get_flavour(bfd_h) == bfd_target_unknown_flavour)   
        DIE("(get_flavour) (%s)", bfd_errmsg(bfd_get_error()));

    render(bfd_h);
    
}

int main(int argc, char *argv[]) {

    if (argc < 2) 
        DIE("Usage: min_file <filename>");
    
    load_file(argv[1]);

    return 1;
}
