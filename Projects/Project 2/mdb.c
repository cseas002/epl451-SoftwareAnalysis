/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h> // for isspace

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
#define MAX_COMMAND_LENGTH 100
#define EXIT 1
#define NOT_EXIT 0

typedef struct breakpoint
{
    long address;
    long instruction;
    unsigned int number;
} BREAKPOINT;

// This could be a C++ map
BREAKPOINT *breakpoints = NULL;          // Global array of structs
int breakpoints_count = 0;               // Number of elements currently in the array
unsigned int next_breakpoint_number = 1; // Initialize the next breakpoint number

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
        char *with_path = (char *)malloc(strlen(program) + 3); // 2 for "./", 1 for null terminator
        sprintf(with_path, "./%s", program);
        return with_path;
    }
}

bool ret_ins(cs_insn insn)
{
    // Check if the mnemonic contains "ret"
    if (strstr(insn.mnemonic, "ret") != NULL)
    {
        return true; // Return true if "ret" is found in the mnemonic
    }
    else
    {
        return false; // Return false otherwise
    }
}
void disassemble(const uint8_t *code, size_t size, long start_address, int ins_count)
{
    csh handle;
    cs_insn *insn;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        fprintf(stderr, "Error: Failed to initialize Capstone\n");
        return;
    }

    // Set Capstone to use AT&T syntax
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    size_t count = cs_disasm(handle, code, size, start_address, 0, &insn);
    if (count > 0)
    {
        for (size_t j = 0; j < count; j++)
        {
            if (j == 0)
                printf("=> ");
            else
                printf("   ");

            printf("\033[0;34m0x%lx:\033[0m ", insn[j].address);
            printf("\033[0m<+%ld>:\t", insn[j].address - start_address);
            printf("\033[0;32m%s\t\033[0;31m%s\033[0m\n", insn[j].mnemonic, insn[j].op_str);
            if (ret_ins(insn[j]))
                break;
        }
        cs_free(insn, count);
    }
    else
    {
        fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
    }

    printf("End of assembler dump.\n");
    cs_close(&handle);
}

void process_inspect(int pid, struct user_regs_struct regs)
{
    const size_t chunk_size = 4;      // Read 4 bytes at a time
    const size_t total_size = 16 * 4; // Read a total of 16 chunks

    // Read total_size bytes of data from the memory address pointed to by regs.rip
    uint8_t *binary_data = (uint8_t *)malloc(total_size);
    if (!binary_data)
    {
        fprintf(stderr, "ERROR: Memory allocation failed!\n");
        return;
    }

    for (size_t offset = 0; offset < total_size; offset += chunk_size)
    {
        long data = ptrace(PTRACE_PEEKDATA, pid, regs.rip + offset, 0);
        if (data == -1)
        {
            fprintf(stderr, "ERROR: Failed to peek data from process memory: %s\n", strerror(errno));
            free(binary_data);
            return;
        }
        memcpy(binary_data + offset, &data, sizeof(data));
    }

    // Disassemble the read data
    disassemble(binary_data, total_size, regs.rip, 10);
    // Clean up
    free(binary_data);
}

long set_breakpoint(int pid, long addr)
{
    /* Backup current code.  */
    long original_ins = 0;

    original_ins = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
    if (original_ins == -1)
    {
        DIE("Error setting breakpoint (peekdata): %s", strerror(errno));
    }

    // fprintf(stderr, "0x%p: 0x%lx\n", (void *)addr, original_ins);

    /* Insert the breakpoint. */
    long trap = (original_ins & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)trap) == -1)
        DIE("(pokedata) %s", strerror(errno));

    /* Resume process.  */
    // if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
    //     DIE("(cont) %s", strerror(errno));

    for (int i = 0; i < breakpoints_count; i++)
    {
        if (breakpoints[i].address == addr)
        {
            breakpoints[i].instruction = original_ins;
        }
    }

    return original_ins;
}

void disas(pid_t pid)
{
    struct user_regs_struct regs;
    // Now, register rip (instruction pointer) has the address of the breakpoint
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        DIE("(getregs) %s", strerror(errno));

    process_inspect(pid, regs);
}

void continue_process(pid_t pid)
{
    fprintf(stderr, "Resuming.\n");

    struct user_regs_struct regs;
    // Get registers
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        DIE("(getregs) %s", strerror(errno));

    // Execute the instruction, and read the previous instruction's breakpoint
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        DIE("(singlestep) %s", strerror(errno));

    waitpid(pid, 0, 0);

    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        DIE("(getregs) %s", strerror(errno));

    // printf("%lx\n", regs.rip);

    // Set the breakpoint back
    set_breakpoint(pid, regs.rip);
}

void step_instruction(pid_t pid)
{
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        DIE("(singlestep) %s", strerror(errno));

    waitpid(pid, 0, 0);
}

BREAKPOINT *get_original_breakpoint(long address)
{
    for (int i = 0; i < breakpoints_count; i++)
    {
        if (breakpoints[i].address == address)
        {
            return &breakpoints[i];
        }
    }
    fprintf(stderr, "Cannot find instruction of address %lx\n", address);
    return NULL;
}

int serve_breakpoint(int pid)
{
    struct user_regs_struct regs;
    // Now, register rip (instruction pointer) has the address of the breakpoint
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        DIE("(getregs) %s", strerror(errno));

    regs.rip--; // Move the regs.rip one place back

    // This will return the breakpoint, with the original instruction as the instruction
    BREAKPOINT *brkpoint = get_original_breakpoint(regs.rip);

    printf("Breakpoint %d, \033[0;34m0x%lx\033[0m\n", brkpoint->number, brkpoint->address);

    if (ptrace(PTRACE_POKEDATA, pid, (void *)brkpoint->address, (void *)brkpoint->instruction) == -1)
        DIE("(pokedata) %s", strerror(errno));

    // regs.rip = addr;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
        DIE("(setregs) %s", strerror(errno));

    return NOT_EXIT;
}

void show_initial_console_messaage()
{
    printf("For help, type \"help\".\n");
    printf("Type \"apropos word\" to search for commands related to \"word\"...\n");
    printf("Reading symbols from test...\n");
    printf("(No debugging symbols found in test)\n");
    // fflush(stdout);
}

void show_console()
{
    printf("(gdb) ");
    // fflush(stdout); // Flush the output to ensure it's displayed immediately
}

void run_tracee_program(pid_t *pid, Elf **elf, Elf_Scn **symtab, char **argv)
{
    // Prepend current directory path if necessary (so I can run with ./mdb test :p)
    char *program = prepend_current_directory(argv[1]);
    /* fork() for executing the program that is analyzed.  */
    *pid = fork();
    switch (*pid)
    {
    case -1: /* error */
        DIE("%s", strerror(errno));
    case 0: /* Code that is run by the child. */
        /* Start tracing.  */
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        /* execvp() is a system call, the child will block and
           the parent must do waitpid().
           The waitpid() of the parent is in the label
           waitpid_for_execvp.
         */

        execvp(program, argv + 1);
        DIE("%s", strerror(errno));
    }

    ptrace(PTRACE_SETOPTIONS, *pid, 0, PTRACE_O_EXITKILL);

    waitpid(*pid, 0, 0);

    for (int i = 0; i < breakpoints_count; i++)
        set_breakpoint(*pid, breakpoints[i].address);

    // Continue the execution
    if (ptrace(PTRACE_CONT, *pid, 0, 0) == -1)
        DIE("(cont) run tracee %s", strerror(errno));
}

// Function to add a new instruction to the array
void add_breakpoint(long address, long original_instruction)
{
    // Increment the count of instructions
    breakpoints_count++;

    // Reallocate memory for the array to accommodate the new instruction
    breakpoints = (BREAKPOINT *)realloc(breakpoints, sizeof(BREAKPOINT) * breakpoints_count);
    if (breakpoints == NULL)
    {
        // Handle memory allocation failure
        fprintf(stderr, "Error: Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    // Assign the values to the new instruction
    breakpoints[breakpoints_count - 1].address = address;
    breakpoints[breakpoints_count - 1].instruction = original_instruction;
    breakpoints[breakpoints_count - 1].number = next_breakpoint_number++;
    // breakpoints[breakpoints_count - 1].ignore = ignore;
}

// Function to free the memory allocated for the array
void cleanup_breakpoints()
{
    free(breakpoints);
    breakpoints = NULL;
    breakpoints_count = 0;
}

bool command_is_empty(char *command)
{
    while (*command)
    {
        if (!isspace(*command))
        {                 // Check if the character is not whitespace
            return false; // Found a non-whitespace character, so the command is not empty
        }
        command++; // Move to the next character
    }
    return true; // All characters are whitespace, so the command is empty
}

bool arg_is_symbol(char *arg)
{
    return true;
}

int run_gdb(char **argv)
{
    char command[MAX_COMMAND_LENGTH];
    Elf *elf = NULL;
    Elf_Scn *symtab = NULL;
    pid_t pid;
    bool process_is_running = false;
    bool process_started = false;

    /* Initilization.  */
    if (elf_version(EV_CURRENT) == EV_NONE)
        DIE("(version) %s", elf_errmsg(-1));

    int fd = open(argv[1], O_RDONLY);

    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf)
        DIE("(begin) %s", elf_errmsg(-1));

    symtab = getSymbolTable(elf); // Not that this might be NULL

    if (!(symtab))
        fprintf(stderr, "Symbol table not found\n");

    show_initial_console_messaage();

    while (true)
    {
        // Show the console prompt again
        show_console();
        if (fgets(command, sizeof(command), stdin) == NULL)
            break;
        // Remove trailing newline character
        command[strcspn(command, "\n")] = '\0';

        // Handle commands here
        if (strcmp(command, "help") == 0)
        {
            printf("This is a help message.\n");
        }
        else if (strcmp(command, "si") == 0)
        {
            step_instruction(pid);
        }
        else if (strcmp(command, "disas") == 0)
        {
            disas(pid);
        }
        else if (strncmp(command, "c", strlen("c")) == 0)
        {
            if (process_started)
            {
                if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
                    DIE("(cont) %s", strerror(errno));
                process_is_running = true;
            }
            else
            {
                printf("Process is not running.\n");
            }
        }
        // Run the child program
        else if (strncmp(command, "r", strlen("r")) == 0)
        {
            if (process_started)
            {
                printf("Process is already running\n");
                continue;
            }
            process_is_running = true;
            process_started = true;
            run_tracee_program(&pid, &elf, &symtab, argv);
            printf("Starting program: %s\n\n", argv[1]);
            // for (int i = 0; i < breakpoints_count; i++)
            //     set_breakpoint(pid, breakpoints[i].address);
        }
        else if (strncmp(command, "b", strlen("b")) == 0)
        {
            char arg[MAX_COMMAND_LENGTH];                // Assuming the maximum length of the symbol name
            int parsed = sscanf(command, "%*s %s", arg); // Skip the first string "b" and parse the symbol name

            if (parsed != 1)
            {
                // Parsing failed, invalid command format
                printf("Invalid command format for breakpoint\n");
                continue;
            }
            char *symbol;
            long address;
            if (arg_is_symbol(arg))
            {
                symbol = arg;
                address = getSymbolAddress(symbol, elf, symtab);
            }
            else
            {
                address = 10;
            }

            if (!address)
            {
                // TODO Add here a question whether to bind later
                fprintf(stderr, "The symbol %s has not been found.\n", symbol);
                continue;
            }
            else
            {
                printf("Breakpoint %d at \033[0;34m0x%lx\033[0m\n", next_breakpoint_number, address);
                // fflush(stdout); // Flush stdout to ensure the message is displayed immediately
            }
            long instruction = 0;
            if (process_started)
            {
                instruction = set_breakpoint(pid, address);
            }
            add_breakpoint(address, instruction); // If instruction == 0, it will add the instructions later. Maybe not the best implementation
        }
        else if (strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0 || strcmp(command, "q") == 0)
        {
            printf("Exiting...\n");
            DIE("Exited");
        }
        // Handle empty command (just Enter)
        else if (command_is_empty(command))
        {
            // Do nothing and continue to prompt
        }
        else
        {
            printf("Unknown command: %s\n", command);
        }

        // If there is a breakpoint, check whether we entered it
        if (process_is_running && breakpoints_count != 0)
        {
            // Check whether the program entered a breakpoint
            waitpid(pid, 0, 0);

            /* We are in the breakpoint.  */
            if (serve_breakpoint(pid) == EXIT)
            {
                printf("EXITED\n");
            }
            process_is_running = false;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc <= 1)
        DIE("Usage: %s <program>", argv[0]);

    csh handle;

    /* Initialize the engine.  */
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;

    /* AT&T */
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    cs_close(&handle);

    run_gdb(argv);

    cleanup_breakpoints();

    return 0;
}
