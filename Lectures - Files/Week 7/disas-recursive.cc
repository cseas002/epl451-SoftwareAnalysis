
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

#include <queue>
#include <map>

#define DIE(...) \
    do { \
        fprintf(stderr, __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)


long unsigned g_text_start = 0;
long unsigned g_text_end = 0;

enum bb_status { UNSEEN, ENQUEUED, SEEN };

/* Instruction classification.  */
bool is_cs_cflow_group(uint8_t g) {
    return (g  == CS_GRP_JUMP) || (g == CS_GRP_CALL) || (g == CS_GRP_RET) || (g == CS_GRP_IRET);
}

bool is_cs_cflow_ins(cs_insn *ins) {
    for (size_t i = 0; i < ins->detail->groups_count; i++) {
        if (is_cs_cflow_group(ins->detail->groups[i])) {
            return true;
        }
    }
    return false;
}

bool is_cs_unconditional_csflow_ins(cs_insn *ins) {
    switch (ins->id) {
        case X86_INS_JMP:
        case X86_INS_LJMP:
        case X86_INS_RET:
        case X86_INS_RETF:
        case X86_INS_RETFQ:
            return true;
        default:
            return false;
    }
}

uint64_t get_cs_ins_immediate_target(cs_insn *ins) {
    cs_x86_op *cs_op;

    for (size_t i = 0; i < ins->detail->groups_count; i++) {
        if (is_cs_cflow_group(ins->detail->groups[i])) {
            for (size_t j = 0; j < ins->detail->x86.op_count; j++) {
                cs_op = &ins->detail->x86.operands[j];
                if (cs_op->type == X86_OP_IMM) 
                    return cs_op->imm;
            }
        }
    }
    return 0;
}


void read_symbol_table(Elf *elf, std::queue<uint64_t> *Q) {
    Elf_Scn *scn, *symtab = NULL;
    Elf_Data *data;
    GElf_Shdr shdr;
    size_t shstrndx;

    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        DIE("(getshdrstrndx) %s", elf_errmsg(-1));
        
    /* Loop over sections.  */
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            DIE("(getshdr) %s", elf_errmsg(-1));
            
        /* Locate symbol table.  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".symtab"))
            symtab = scn;
    }

    /* Get the descriptor.  */
    if (gelf_getshdr(symtab, &shdr) != &shdr)
        DIE("(getshdr) %s", elf_errmsg(-1));

    data = elf_getdata(symtab, NULL);
    int count = shdr.sh_size / shdr.sh_entsize;

    for (int i = 0; i < count; ++i) {
        GElf_Sym sym;
        gelf_getsym(data, i, &sym);
        if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC &&
            (sym.st_value >= g_text_start && sym.st_value < g_text_end)) {
            fprintf(stderr, "Queueing %s at %016lx.\n",  elf_strptr(elf, shdr.sh_link, sym.st_name), sym.st_value);
            Q->push(sym.st_value);
        }
    }
}

Elf_Data * find_text(Elf *elf) {
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    Elf_Data *data = NULL;

    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        DIE("(getshdrstrndx) %s", elf_errmsg(-1));

    /* Loop over sections.  */
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr)
            DIE("(getshdr) %s", elf_errmsg(-1));

        /* Locate .text  */
        if (!strcmp(elf_strptr(elf, shstrndx, shdr.sh_name), ".text")) {
            data = elf_getdata(scn, data); 
            if (!data)
                DIE("(getdata) %s", elf_errmsg(-1));

            g_text_start = shdr.sh_addr;
            g_text_end = g_text_start + shdr.sh_size;

            return (data);
        }
    }
    return NULL;
}

void print_ins(cs_insn *ins) {

    fprintf(stderr, "0x%016lx:\t%s\t\t%s\n", ins->address, ins->mnemonic, ins->op_str);
}

void disas_r(char *filename, csh handle) {

    Elf *elf;
    std::queue<uint64_t> Q;
    std::map<uint64_t, bb_status> BB;
    uint64_t addr, offset, target;
    const uint8_t *pc;
    size_t n;
    cs_insn *cs_ins;

    /* Initilization.  */
    if (elf_version(EV_CURRENT) == EV_NONE)
        DIE("(version) %s", elf_errmsg(-1));

    int fd = open(filename, O_RDONLY);

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        DIE("(begin) %s", elf_errmsg(-1));

    Elf_Data * text = find_text(elf);

    if (!text) 
        DIE("(find_text) %s", elf_errmsg(-1));

    read_symbol_table(elf, &Q);

    /* Start the dissaembly.  */
    while (!Q.empty()) {
        /* Process the next address.  */
        addr = Q.front();
        Q.pop();
    
        offset = addr - g_text_start;
        pc = (const unsigned char *) text->d_buf;
        pc += offset;
        n = g_text_end - g_text_start; 
    
        cs_ins = cs_malloc(handle);
        fprintf(stderr, "Starting at 0x%016lx\n", addr);
        while (cs_disasm_iter(handle, &pc, &n, &addr, cs_ins)) {
            if (cs_ins->id == X86_INS_INVALID || cs_ins->size == 0)
                break;
    
            /* We disassembled this address.  */
            BB[cs_ins->address] = SEEN; 
            print_ins(cs_ins);
       
            /* We found a branch.  */
            if (is_cs_cflow_ins(cs_ins)) {
                target = get_cs_ins_immediate_target(cs_ins);
                /* Push target in the queue if we haven't already visited the code.  */
                if (target && BB[target] != ENQUEUED && BB[target] != SEEN && (target >= g_text_start && target < g_text_end)) {
                    Q.push(target);
                    BB[target] = ENQUEUED;
                    fprintf(stderr, "Adding target: 0x%016lx\n", target);
                }
            }
    
            /* We reacched the end of the fuction. */ 
            if (cs_ins->id == X86_INS_RET) break;
        }
    } 

    cs_free(cs_ins, 1);
    cs_close(&handle); 
}


int main(int argc, char *argv[]) {

    /* Initialize the engine.  */
    csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;

    /* AT&T */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    /* detail mode.  */
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    disas_r(argv[1], handle);    

    cs_close(&handle);

    return 1;
}
