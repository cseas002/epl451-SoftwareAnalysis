#include <stdio.h>

#include <capstone/capstone.h>

void disas(csh handle, const unsigned char *buffer) {
	cs_insn *insn;
	size_t count;

	count = cs_disasm(handle, buffer, 32, 0x0, 0, &insn);

    if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			fprintf(stderr, "0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}
		cs_free(insn, count);
	} else
		fprintf(stderr, "ERROR: Failed to disassemble given code!\n");

}

int main(int argc, char *argv[]) {

    const unsigned char * code = (unsigned char *) "\x55\x48\x89\xe5\x48\x83\xec\x10\x89\x7d\xfc\x48\x89\x75\xf0\xbf\x00\x00\x00\x00\xe8\x00\x00\x00\x00\xb8\x00\x00\x00\x00\xc9\xc3";            
    /* Initialize the engine.  */
    csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return -1;

    /* AT&T */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);


    disas(handle, code); 

    cs_close(&handle);

    return 1;
}
