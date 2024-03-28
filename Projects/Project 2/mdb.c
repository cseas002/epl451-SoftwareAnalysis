/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>

/* Elf*/
#include "elf_mdb_helpers.h"

#define TOOL "min_gdb"

#define die(...)                                \
    do                                          \
    {                                           \
        fprintf(stderr, TOOL ": " __VA_ARGS__); \
        fputc('\n', stderr);                    \
        exit(EXIT_FAILURE);                     \
    } while (0)

#define BREAKPOINT_ADDR 0x0000000000401838

// Function to prepend "./" to program name if not already present
char *prepend_current_directory(const char *program)
{
    // Check if the program already starts with "./"
    if (strncmp(program, "./", 2) == 0)
    {
        // Program already starts with "./", no modification needed
        return strdup(program);
    }
    else
    {
        // Program does not start with "./", prepend it
        char *with_path = malloc(strlen(program) + 3); // 2 for "./", 1 for null terminator
        sprintf(with_path, "./%s", program);
        return with_path;
    }
}

void process_inspect(int pid)
{
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        die("%s", strerror(errno));

    long current_ins = ptrace(PTRACE_PEEKDATA, pid, regs.rip, 0);
    if (current_ins == -1)
        die("(peekdata) %s", strerror(errno));

    fprintf(stderr, "=> 0x%llx: 0x%lx\n", regs.rip, current_ins);
}

long set_breakpoint(int pid, long addr)
{
    /* Backup current code.  */
    long previous_code = 0;
    previous_code = ptrace(PTRACE_PEEKDATA, pid, (void *)BREAKPOINT_ADDR, 0);
    if (previous_code == -1)
        die("setting breakpoint (peekdata) %s", strerror(errno));

    fprintf(stderr, "0x%p: 0x%lx\n", (void *)BREAKPOINT_ADDR, previous_code);

    /* Insert the breakpoint. */
    long trap = (previous_code & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)BREAKPOINT_ADDR, (void *)trap) == -1)
        die("(pokedata) %s", strerror(errno));

    /* Resume process.  */
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
        die("(cont) %s", strerror(errno));

    return previous_code;
}

void process_step(int pid)
{

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        die("(singlestep) %s", strerror(errno));

    waitpid(pid, 0, 0);
}

void serve_breakpoint(int pid, long original_instruction)
{
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        die("(getregs) %s", strerror(errno));

    process_inspect(pid);
    getchar();

    fprintf(stderr, "Resuming.\n");

    if (ptrace(PTRACE_POKEDATA, pid, (void *)BREAKPOINT_ADDR, (void *)original_instruction) == -1)
        die("(pokedata) %s", strerror(errno));

    regs.rip = BREAKPOINT_ADDR;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
        die("(setregs) %s", strerror(errno));
}

int run_gdb(pid_t pid, csh handle, char *filename)
{
    Elf *elf;

    /* Initilization.  */
    if (elf_version(EV_CURRENT) == EV_NONE)
        DIE("(version) %s", elf_errmsg(-1));

    int fd = open(filename, O_RDONLY);

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        DIE("(begin) %s", elf_errmsg(-1));

    Elf_Scn *symtab = getSymbolTable(elf); // Not that this might be NULL

    /* Code that is run by the parent.  */
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
    waitpid(pid, 0, 0);

    long address = getSymbolAddress("main");
    // long address = 10;
    long original_instruction = set_breakpoint(pid, address);

    waitpid(pid, 0, 0);

    /* We are in the breakpoint.  */
    serve_breakpoint(pid, original_instruction);

    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
        die("(cont) %s", strerror(errno));

    waitpid(pid, 0, 0);
}

int main(int argc, char **argv)
{
    if (argc <= 1)
        die("Usage: %s <program>", argv[0]);

    /* Initialize the engine.  */
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;

    /* AT&T */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    cs_close(&handle);

    // Prepend current directory path if necessary (so I can run with ./mdb test :p)
    char *program = prepend_current_directory(argv[1]);
    /* fork() for executing the program that is analyzed.  */
    pid_t pid = fork();
    switch (pid)
    {
    case -1: /* error */
        die("%s", strerror(errno));
    case 0: /* Code that is run by the child. */
        /* Start tracing.  */
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        /* execvp() is a system call, the child will block and
           the parent must do waitpid().
           The waitpid() of the parent is in the label
           waitpid_for_execvp.
         */

        execvp(program, argv + 1);
        die("%s", strerror(errno));
    }

    run_gdb(pid, handle, program);

    return 0;
}
