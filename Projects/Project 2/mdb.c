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
#include <sys/prctl.h>

/* Linux */
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/personality.h>

// #include <termios.h>
// #include <conio.h>

/* Elf*/
#include "elf_mdb_helpers.h"

#define TOOL "min_gdb"
#define MAX_COMMAND_LENGTH 100
#define DISAS_INS_COUNT 10
#define MAX_INS_FROM_FUNC_START 0 // All instructions in a function
#define SIGTRAP 5
#define FOUND 1
#define NOT_FOUND 0

#define MAX_LINE_LENGTH 256

typedef struct breakpoint
{
    long address;
    long instruction;
    unsigned int number;
} BREAKPOINT;

typedef struct
{
    Elf64_Addr current_address;
    Elf64_Addr end_address;
    const char *name;
} FunctionInfo;

// This could be a C++ map
BREAKPOINT *breakpoints = NULL;          // Global array of structs
int breakpoints_count = 0;               // Number of elements currently in the array
unsigned int next_breakpoint_number = 1; // Initialize the next breakpoint number

unsigned long exec_aslr_offset;
unsigned long lib_aslr_offset;

// Function to disassemble the function and find its start and end addresses
void disassemble_function(Elf *elf, Elf_Scn *scn, GElf_Shdr *shdr, FunctionInfo *function)
{
    // Get section data
    Elf_Data *data = elf_getdata(scn, NULL);
    if (!data)
    {
        fprintf(stderr, "Failed to get section data\n");
        return;
    }

    // Initialize Capstone
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        fprintf(stderr, "Failed to initialize Capstone\n");
        return;
    }

    // Disassemble the section
    size_t count;
    cs_insn *insn;
    count = cs_disasm(handle, data->d_buf + shdr->sh_offset, shdr->sh_size, shdr->sh_addr, 0, &insn);
    if (count > 0)
    {
        // Update function info with start and end addresses
        function->current_address = insn[0].address;
        function->end_address = insn[count - 1].address + insn[count - 1].size;
        cs_free(insn, count);
    }

    // Close Capstone
    cs_close(&handle);
}

bool arg_is_symbol(char *arg)
{
    // Check each character of the argument
    while (*arg != '\0')
    {
        if (*arg == '*')
            return false;
        // If any character is not alphanumeric, return false
        if (!isalnum(*arg))
        {
            return false;
        }
        arg++; // Move to the next character
    }
    return true; // If all characters are alphanumeric, return true
}

// Function to assign the address based on the input argument
long assign_address(char *arg, Elf *elf, Elf_Scn *symtab)
{
    long address = 0;
    if (arg_is_symbol(arg))
    {
        // If the argument is a symbol, get its address
        address = getSymbolAddress(arg, elf, symtab);
    }
    else
    {
        if (strncmp(arg, "*0x", 3) == 0)
        {
            // Extract the hexadecimal number part after "*0x"
            const char *hex_str = arg + 3;
            // Convert the hexadecimal string to a long integer
            char *endptr;
            long address = strtol(hex_str, &endptr, 16);
            // Check if conversion was successful
            if (endptr != hex_str)
            {
                return address;
            }
        }
    }
    return address;
}

// Function to find the function containing the given address
Elf64_Sym *find_address_function(Elf *elf, Elf64_Addr address, char **function_name)
{
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    size_t shstrndx;
    const char *section_name;
    Elf64_Sym *symtab = NULL;
    char *sym_name;
    Elf_Data *sym_data;
    size_t sym_num, i;

    // return symtab;

    // Get the section name string table index
    elf_getshdrstrndx(elf, &shstrndx);

    // Iterate through sections
    while ((scn = elf_nextscn(elf, scn)) != NULL)
    {
        // Get section header
        if (gelf_getshdr(scn, &shdr) != &shdr)
        {
            fprintf(stderr, "Failed to get section header\n");
            continue;
        }

        // Get section name
        section_name = elf_strptr(elf, shstrndx, shdr.sh_name);

        if (!section_name)
        {
            fprintf(stderr, "Failed to get section name\n");
            continue;
        }

        // Check if it's a symbol table section
        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM)
        {
            // Get symbol table data
            sym_data = elf_getdata(scn, NULL);
            if (!sym_data)
            {
                fprintf(stderr, "Failed to get symbol table data\n");
                continue;
            }

            // Get the number of symbols
            sym_num = shdr.sh_size / shdr.sh_entsize;

            // Get the symbol table
            symtab = (Elf64_Sym *)sym_data->d_buf;

            // Iterate through symbols
            for (i = 0; i < sym_num; ++i)
            {
                sym_name = elf_strptr(elf, shdr.sh_link, symtab[i].st_name);

                if (!sym_name)
                {
                    fprintf(stderr, "Failed to get symbol name\n");
                    continue;
                }

                // Check if the symbol contains the address
                if (address >= symtab[i].st_value && address < symtab[i].st_value + symtab[i].st_size)
                {
                    if (function_name)
                    {
                        *function_name = malloc(sizeof(char) * (strlen(sym_name) + 1));
                        strcpy(*function_name, sym_name);
                    }

                    return &symtab[i]; // return the symbol's details
                }
            }
        }
    }

    return NULL; // Address not found in any function
}

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

BREAKPOINT get_breakpoint(long address)
{
    BREAKPOINT failure = {0, 0, 0};

    for (int i = 0; i < breakpoints_count; i++)
    {
        if (address == breakpoints[i].address)
        {
            return breakpoints[i];
        }
    }
    return failure;
}

// This function will replace the int3 added by breakpoints to their original instructions
int find_and_change_int3(uint8_t *code, int offset, long address)
{
    BREAKPOINT breakpoint = get_breakpoint(address);
    if (breakpoint.number == 0)
    { // Failure
        return NOT_FOUND;
    }

    code[offset] = (breakpoint.instruction & 0xFF); // Get the last byte
    return FOUND;
}

void remove_int3(uint8_t *code, size_t size, long start_address, int ins_count)
{
    csh handle;
    cs_insn *insn;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        fprintf(stderr, "Error: Failed to initialize Capstone\n");
        return;
    }
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    bool valid;
    do
    {
        valid = true;
        size_t count = cs_disasm(handle, code, size, start_address, ins_count, &insn);
        if (count > 0)
        {
            // Get the instructions one by one
            for (size_t j = 0; j < count; j++)
            {
                // If you found an int3, replace it with the original instruction
                if (strcmp(insn[j].mnemonic, "int3") == 0)
                {
                    int offset = insn[j].address - start_address;
                    if (find_and_change_int3(code, offset, insn[j].address) == FOUND)
                    {
                        valid = false;
                        break;
                    }
                }
            }
            cs_free(insn, count);
        }
    } while (!valid);
    cs_close(&handle);
}

void disassemble(uint8_t *code, size_t size, long current_address, int ins_count, char *function_name, Elf64_Sym *function_start)
{
    long function_start_address = current_address;

    if (function_start)
    {
        printf("Dump of assembler code for function \033[0;33m%s\033[0m:\n", function_name);
        function_start_address = function_start->st_value;

        // If there are breakpoints in the code, remove them
        remove_int3(code, size, function_start_address, ins_count);
    }

    csh handle;
    cs_insn *insn;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        fprintf(stderr, "Error: Failed to initialize Capstone\n");
        return;
    }

    // Set Capstone to use Intel syntax
    // cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    // or, set Capstone to use AT&T syntax
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    // Disassemble the instructions starting from the function start,
    // and print 4 instructions prior the the start address, the start address instruction, and 5 after
    size_t count = cs_disasm(handle, code, size, function_start_address, ins_count, &insn);
    bool found_address = false;
    int start_from = 0;

    // insn_to_be_printed = malloc(DISAS_INS_COUNT * sizeof(cs_insn));
    if (count > 0)
    {
        // Get the instructions one by one
        for (size_t j = 0; j < count; j++)
        {
            // If the start address is found
            if (insn[j].address == current_address)
            {
                // Copy the 4 prior elements, and the current one
                if (j > 4)
                {
                    start_from = j - 4;
                }
                found_address = true;
                break;
            }
        }
        if (found_address)
        {
            for (int i = start_from; i < start_from + 10; i++)
            {
                if (insn[i].address == current_address)
                    printf("=> ");
                else
                    printf("   ");

                printf("\033[0;34m0x%lx:\033[0m ", insn[i].address);
                printf("\033[0m<+%ld>:\t", insn[i].address - function_start_address);
                printf("\033[0;32m%s\t\033[0;31m%s\033[0m\n", insn[i].mnemonic, insn[i].op_str);
                // If you found a return instruction, then stop
                if (ret_ins(insn[i]))
                    break;
            }
            // cs_free(insn_to_be_printed, count2);
        }
        else
        {
            printf("Function start: %lx\n", function_start_address);
        }
    }
    else
    {
        fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
    }

    cs_free(insn, count);
    printf("End of assembler dump.\n");
    cs_close(&handle);
}

void process_inspect(int pid, struct user_regs_struct regs, Elf *elf)
{
    const size_t chunk_size = 4;      // Read 4 bytes at a time
    const size_t total_size = 40 * 4; // Read a total of 40 chunks

    // Read total_size bytes of data from the memory address pointed to by regs.rip
    uint8_t *binary_data = (uint8_t *)malloc(total_size);
    if (!binary_data)
    {
        fprintf(stderr, "ERROR: Memory allocation failed!\n");
        return;
    }

    long current_address = regs.rip;
    long function_start_address = current_address;
    char *function_name = NULL;
    Elf64_Sym *function_start = find_address_function(elf, current_address, &function_name);

    // If no function start found, then the function start is the current_address
    if (function_start)
        function_start_address = function_start->st_value;

    // Load the data from the function start;
    for (size_t offset = 0; offset < total_size; offset += chunk_size)
    {
        long data = ptrace(PTRACE_PEEKDATA, pid, function_start_address + offset, 0);
        if (data == -1)
        {
            fprintf(stderr, "ERROR: Failed to peek data from process memory: %s\n", strerror(errno));
            free(binary_data);
            return;
        }
        memcpy(binary_data + offset, &data, sizeof(data));
    }

    // Disassemble the read data
    disassemble(binary_data, total_size, current_address, MAX_INS_FROM_FUNC_START, function_name, function_start);
    // Clean up
    free(binary_data);
}

long set_breakpoint(int pid, long addr)
{
    /* Backup current code.  */
    long original_ins = 0;
    // addr += 0x555555554000;
    // addr += 0x555555554000;
    // fprintf(stderr, "0x%lx: 0x%lx\n", addr, original_ins);
    // unsigned long addr2 = 0x555515555174;
    // while (1)
    // {
    //     if (ptrace(PTRACE_PEEKDATA, pid, (void *)addr2, 0) != -1)
    //     {
    //         printf("AAAAAA %lx\n", addr2);
    //         break;
    //     }
    //     addr2++;
    // }

    original_ins = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, 0);
    if (original_ins == -1)
    {
        DIE("Error setting breakpoint (peekdata): %s", strerror(errno));
    }

    /* Insert the breakpoint. */
    long trap = (original_ins & 0xFFFFFFFFFFFFFF00) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void *)addr, (void *)trap) == -1)
        DIE("(pokedata) %s", strerror(errno));

    // printf("POKED Data on address %lx\n", addr);

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

void disas(pid_t pid, Elf *elf)
{
    struct user_regs_struct regs;
    // Now, register rip (instruction pointer) has the address of the breakpoint
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        DIE("(getregs) %s", strerror(errno));

    process_inspect(pid, regs, elf);
}

void continue_process(pid_t pid)
{
    fprintf(stderr, "Continuing.\n\n");

    struct user_regs_struct regs;
    // Get registers
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        DIE("(getregs) aaaaa %s", strerror(errno));

    // Execute one instruction
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        DIE("(singlestep) %s", strerror(errno));

    waitpid(pid, 0, 0);

    BREAKPOINT prev_breakpoint = get_breakpoint(regs.rip);

    if (prev_breakpoint.number != 0)
    {
        // printf("Setting back breakpoint\n");
        // Set the breakpoint back
        set_breakpoint(pid, regs.rip);
    }

    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
        DIE("(cont) set_back_breakpoint %s", strerror(errno));
}

bool step_instruction(Elf *elf, pid_t pid)
{
    struct user_regs_struct regs;
    // Get previous
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        DIE("(getregs) %s", strerror(errno));

    long old_rip = regs.rip;

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1)
        DIE("(singlestep) %s", strerror(errno));

    waitpid(pid, 0, 0);

    // Get registers
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        DIE("(getregs) %s", strerror(errno));

    char *function_name = "?";

    find_address_function(elf, regs.rip, &function_name);
    if (!function_name)
        function_name = "?";

    printf("\033[0;34m0x%llx\033[0m in \033[0;33m%s\033[0m ()\n", regs.rip, function_name);

    // Set back the breakpoint
    BREAKPOINT prev_breakpoint = get_breakpoint(old_rip);

    if (prev_breakpoint.number != 0)
    {
        // printf("Setting back\n");
        set_breakpoint(pid, old_rip);
    }

    // If this instruction is a breakpoint, then we need to continue so it will stop here
    BREAKPOINT breakpoint = get_breakpoint(regs.rip);

    // If such a breakpoint exist, then continue
    if (breakpoint.number != 0)
    {
        printf("Entered breakpoint!\n");
        // // Continue the execution
        if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
            DIE("(cont) run tracee %s", strerror(errno));

        return true;
    }

    return false;
    // waitpid(pid, 0, 0);
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

// Comparison function for qsort
int compare_breakpoints(const void *a, const void *b)
{
    const BREAKPOINT *bp1 = (const BREAKPOINT *)a;
    const BREAKPOINT *bp2 = (const BREAKPOINT *)b;
    // Compare addresses
    if (bp1->address < bp2->address)
        return -1;
    if (bp1->address > bp2->address)
        return 1;
    return 0;
}

// Function to sort breakpoints array
void sort_breakpoints()
{
    qsort(breakpoints, breakpoints_count, sizeof(BREAKPOINT), compare_breakpoints);
}

long find_correct_instruction(long address)
{
    long correct_instruction;

    bool found = false;

    for (int i = 0; i < breakpoints_count; i++)
    {
        // Find the correct instruction
        if (breakpoints[i].address == address)
        {
            found = true;
            BREAKPOINT breakpoint = breakpoints[i];
            correct_instruction = breakpoint.instruction;
            for (int offset = 1; offset < 8; offset++)
            {
                BREAKPOINT next_byte_possible_breakpoint = get_breakpoint(breakpoint.address + offset);
                // If there is such a breakpoint
                if (next_byte_possible_breakpoint.number != 0)
                {
                    // printf("Adding back CC in %lx\n", next_byte_possible_breakpoint.address);
                    // Add its int3
                    switch (offset)
                    {
                    case 1:
                        correct_instruction = (correct_instruction & 0xFFFFFFFFFFFF00FF) | 0xCC00;
                        break;
                    case 2:
                        correct_instruction = (correct_instruction & 0xFFFFFFFFFF00FFFF) | 0xCC0000;
                        break;
                    case 3:
                        correct_instruction = (correct_instruction & 0xFFFFFFFF00FFFFFF) | 0xCC000000;
                        break;
                    case 4:
                        correct_instruction = (correct_instruction & 0xFFFFFF00FFFFFFFF) | 0xCC00000000;
                        break;
                    case 5:
                        correct_instruction = (correct_instruction & 0xFFFF00FFFFFFFFFF) | 0xCC0000000000;
                        break;
                    case 6:
                        correct_instruction = (correct_instruction & 0xFF00FFFFFFFFFFFF) | 0xCC000000000000;
                        break;
                    case 7:
                        correct_instruction = (correct_instruction & 0x00FFFFFFFFFFFFFF) | 0xCC00000000000000;
                        break;
                    }
                }
            }

            break;
        }
    }

    if (!found)
        printf("Something is really wrong\n");

    return correct_instruction;
}

void serve_breakpoint(Elf *elf, int pid)
{
    struct user_regs_struct regs;
    // Now, register rip (instruction pointer) has the address of the breakpoint
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
        DIE("(getregs) %s", strerror(errno));

    regs.rip--; // Set the instruction pointer to back to the real instruction

    // This will return the breakpoint, with the original instruction as the instruction
    BREAKPOINT *brkpoint = get_original_breakpoint(regs.rip);

    char *function_name = "?";
    find_address_function(elf, regs.rip, &function_name);

    printf("Breakpoint %d, \033[0;34m0x%lx\033[0m in \033[0;33m%s\033[0m ()\n", brkpoint->number, brkpoint->address, function_name);

    // There might be a problem here: If two breakpoints are near, it will remove the int3
    // So we need to check that
    long correct_instruction = find_correct_instruction(brkpoint->address); // brkpoint->instruction; // find_correct_instruction(brkpoint->address);

    // printf("INS: %lx\n", correct_instruction);
    if (ptrace(PTRACE_POKEDATA, pid, (void *)brkpoint->address, (void *)correct_instruction) == -1)
        DIE("(pokedata) %s", strerror(errno));

    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1)
        DIE("(setregs) %s", strerror(errno));

    disas(pid, elf);
}

void show_initial_console_messaage()
{
    printf("For help, type \"help\".\n");
    // printf("Type \"apropos word\" to search for commands related to \"word\"...\n");
    printf("Reading symbols from test...\n");
    // fflush(stdout);
}

void show_console()
{
    printf("(gdb) ");
    // fflush(stdout); // Flush the output to ensure it's displayed immediately
}

void run_tracee_program(pid_t *pid, Elf **elf, Elf_Scn **symtab, char **argv, pid_t *child_pid)
{
    // Prepend current directory path if necessary (so I can run with ./mdb test :p)
    char *program = prepend_current_directory(argv[1]);
    /* fork() for executing the program that is analyzed.  */

    int pipe_fd[2];         // Pipe file descriptors
    char child_pid_str[16]; // Buffer to store child PID as string

    if (pipe(pipe_fd) == -1)
    {
        DIE("Pipe failed: %s", strerror(errno));
    }

    *pid = fork();
    switch (*pid)
    {
    case -1: /* error */
        DIE("%s", strerror(errno));
    case 0: /* Code that is run by the child. */
        /* Disable ASLR (Address Space Layout Randomization) */
        if (personality(0xffffffff & ~ADDR_NO_RANDOMIZE) == -1)
        {
            DIE("Failed to disable ASLR: %s", strerror(errno));
        }

        /* Disable ASLR (Address Space Layout Randomization) */
        if (personality(ADDR_NO_RANDOMIZE) == -1)
        {
            DIE("Failed to disable ASLR: %s", strerror(errno));
        }
        /* Disable ASLR (Address Space Layout Randomization) */
        if (prctl(PR_SET_DUMPABLE, 0) == -1)
        {
            DIE("Failed to disable ASLR: %s", strerror(errno));
        }
        /* Start tracing.  */
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        /* execvp() is a system call, the child will block and
           the parent must do waitpid().
           The waitpid() of the parent is in the label
           waitpid_for_execvp.
         */

        /* Duplicate the pipe file descriptor */
        close(pipe_fd[0]);               // Close the read end of the pipe
        dup2(pipe_fd[1], STDOUT_FILENO); // Redirect stdout to the write end of the pipe

        pid_t child_pid_in_child = getpid();
        // Convert child PID to string
        snprintf(child_pid_str, sizeof(child_pid_str), "%d", child_pid_in_child);

        // Write child PID to the pipe, so the parent can see it
        if (write(pipe_fd[1], child_pid_str, strlen(child_pid_str) + 1) == -1)
        {
            DIE("Write to pipe failed: %s", strerror(errno));
        }

        execvp(program, argv + 1);
        DIE("%s", strerror(errno));
    }
    // Parent process
    // Close write end of the pipe
    close(pipe_fd[1]);

    // Read child PID from the pipe
    ssize_t num_bytes = read(pipe_fd[0], child_pid_str, sizeof(child_pid_str));
    if (num_bytes == -1)
    {
        DIE("Read from pipe failed: %s", strerror(errno));
    }

    // Now we can save the child pid
    *child_pid = atoi(child_pid_str);

    ptrace(PTRACE_SETOPTIONS, *pid, 0, PTRACE_O_EXITKILL);

    waitpid(*pid, 0, 0);

    for (int i = 0; i < breakpoints_count; i++)
    {
        set_breakpoint(*pid, breakpoints[i].address);
        // printf("Breakpoint %lx set \n", breakpoints[i].address);
    }

    // Continue the execution
    if (ptrace(PTRACE_CONT, *pid, 0, 0) == -1)
        DIE("(cont) run tracee %s", strerror(errno));
}

// Function to add a new instruction to the array
void add_breakpoint(long address, long original_instruction)
{
    if (breakpoints)
    {
        for (int i = 0; i < breakpoints_count; i++)
            if (address == breakpoints[i].address)
            {
                printf("Breakpoint already exists. Skipping\n");
                return;
            }
    }
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

    // Sort the breakpoints array based on their address
    sort_breakpoints();
}

bool remove_breakpoint(int breakpoint_no)
{
    // Find the index of the breakpoint to remove
    int remove_index = -1;
    for (int i = 0; i < breakpoints_count; i++)
    {
        if (breakpoints[i].number == breakpoint_no)
        {
            remove_index = i;
            break;
        }
    }

    // If the breakpoint was not found, return false
    if (remove_index == -1)
    {
        return false;
    }

    // Shift the elements after the removed breakpoint
    for (int i = remove_index; i < breakpoints_count - 1; i++)
    {
        breakpoints[i] = breakpoints[i + 1];
    }

    // Decrement the count of breakpoints
    breakpoints_count--;

    if (breakpoints_count == 0)
    {
        free(breakpoints);
        breakpoints = NULL;
        return true;
    }
    // Reallocate memory to reduce the size of the array
    breakpoints = (BREAKPOINT *)realloc(breakpoints, sizeof(BREAKPOINT) * breakpoints_count);
    if (breakpoints == NULL)
    {
        // Handle memory allocation failure
        fprintf(stderr, "Error: Memory reallocation failed\n");
        exit(EXIT_FAILURE);
    }

    return true; // Breakpoint removed successfully
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

void list_breakpoints()
{
    if (!breakpoints)
    {
        printf("\nNo breakpoints are set\n\n");
        return;
    }

    printf("List of current breakpoints:\n");
    for (int i = 0; i < breakpoints_count; i++)
    {
        printf("Breakpoint %d at \033[0;34m0x%lx\033[0m\n", breakpoints[i].number, breakpoints[i].address);
    }

    printf("\n");
}

void clearInputBuffer()
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;
}

int run_gdb(char **argv)
{
    char command[MAX_COMMAND_LENGTH], prev_command[MAX_COMMAND_LENGTH];
    Elf *elf = NULL;
    Elf_Scn *symtab = NULL;
    pid_t pid, child_pid;
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
        // Handle empty command (just Enter)
        if (command_is_empty(command))
        {
            // Execute the previous command
            strcpy(command, prev_command);
        }
        // Handle empty command (just Enter)
        if (command_is_empty(command))
        {
            // Do nothing (this will happen if the user presses enter the first time)
        }
        else if (strcmp(command, "help") == 0)
        {
            printf("This is a help message.\n");
        }
        else if (strncmp(command, "r", strlen("r")) == 0)
        {
            // Run the child program
            if (process_started)
            {
                printf("Process is already running\n");
                continue;
            }
            process_is_running = true;
            process_started = true;
            run_tracee_program(&pid, &elf, &symtab, argv, &child_pid);
            printf("Starting program: \033[0;33m%s\033[0m\n\n", argv[1]);
            // for (int i = 0; i < breakpoints_count; i++)
            //     set_breakpoint(pid, breakpoints[i].address);
        }
        else if (strncmp(command, "b", strlen("b")) == 0)
        {
            char arg[MAX_COMMAND_LENGTH - 1];            // Assuming the maximum length of the symbol name
            int parsed = sscanf(command, "%*s %s", arg); // Skip the first string "b" and parse the symbol name

            if (parsed != 1)
            {
                // Parsing failed, invalid command format
                printf("Invalid command format for breakpoint\n");
                continue;
            }

            long address = assign_address(arg, elf, symtab);

            if (!address)
            {
                // TODO Add here a question whether to bind later
                fprintf(stderr, "The symbol or address has not been found.\n");
                continue;
            }

            // fflush(stdout); // Flush stdout to ensure the message is displayed immediately

            long instruction = 0;
            // address += 0x555555554000;
            if (process_started)
            {
                instruction = set_breakpoint(pid, address);
            }
            add_breakpoint(address, instruction); // If instruction == 0, it will add the instructions later. Maybe not the best implementation

            printf("Breakpoint %d at \033[0;34m0x%lx\033[0m\n", next_breakpoint_number - 1, address);
        }
        else if (strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0 || strcmp(command, "q") == 0)
        {
            if (process_started)
            {
                printf("A debugging session is active.\n\n\tInferior 1 [process %d] will be killed.\n\nQuit anyway? (y or n) ", child_pid);
                fflush(stdout); // Ensure prompt is displayed immediately

                char response[2];
                // Read user input
                if (fgets(response, sizeof(response), stdin) != NULL)
                {
                    if (response[0] == 'y' || response[0] == 'Y')
                    {
                        // Kill the child process using ptrace
                        if (ptrace(PTRACE_KILL, child_pid, NULL, NULL) == -1)
                        {
                            DIE("Failed to kill child process: %s", strerror(errno));
                        }
                        // Wait for the child process to terminate
                        waitpid(child_pid, NULL, 0);
                        printf("Child process %d killed.\n", child_pid);
                        DIE("Exited");
                    }
                    else
                    {
                        printf("\n");
                    }
                }
                else
                {
                    // Error or EOF while reading input
                    printf("Error reading input.\n");
                }
                // Clear input buffer
                clearInputBuffer();
            }
            else
            {
                DIE("Exited");
            }
        }
        else if (strcmp(command, "l") == 0)
        {
            list_breakpoints();
        }
        else if (strcmp(command, "disas") != 0 && strncmp(command, "d", strlen("d")) == 0)
        {
            if (!breakpoints)
            {
                printf("There are no breakpoints\n\n");
                continue;
            }
            char arg[MAX_COMMAND_LENGTH - 1];            // Assuming the maximum length of the symbol name
            int parsed = sscanf(command, "%*s %s", arg); // Skip the first string "d" and parse the symbol name

            int breakpoint_no = atoi(arg);

            if (parsed != 1 || (breakpoint_no == 0 && strcmp(arg, "0") != 0))
            {
                // atoi failed to convert the string to an integer
                printf("Invalid input: %s\n", arg);
            }
            else if (!remove_breakpoint(breakpoint_no))
            {
                printf("Breakpoint %d not found\n", breakpoint_no);
            }
            else
            {
                printf("Breakpoint %d removed.\n", breakpoint_no);
            }
        }

        // The process MUST have been started to execute these commands
        else if (process_started)
        {
            if (strcmp(command, "si") == 0)
            {
                process_is_running = step_instruction(elf, pid);
            }
            else if (strcmp(command, "disas") == 0)
            {
                disas(pid, elf);
            }
            else if (strcmp(command, "c") == 0)
            {
                continue_process(pid);
                // if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
                //     DIE("(cont) %s", strerror(errno));
                process_is_running = true;
            }
            else
            {
                printf("Unknown command: %s\n", command);
            }
        }
        else
        {
            // If the command is a valid command but the process hasn't started, prompt it
            if (!(strcmp(command, "si") && strcmp(command, "disas") && strcmp(command, "c") && strcmp(command, "ni")))
                printf("Process is not running.\n");
            else
                printf("Unknown command: %s\n", command);
        }

        // Save the previous command, if it's si
        if (strcmp(command, "si") == 0)
            strcpy(prev_command, command);

        // If there is a breakpoint, check whether we entered it
        if (process_is_running)
        {
            int status;
            // Wait for the child process to change state
            waitpid(pid, &status, 0);

            if (WIFEXITED(status)) // Check if the child process exited normally
            {

                printf("[Inferior 1 (process %d) exited with code %d]\n", pid, WEXITSTATUS(status));
                process_is_running = false;
                process_started = false;
            }
            else if (WIFSTOPPED(status)) // Check if the child process stopped
            {
                if (WSTOPSIG(status) == SIGTRAP) // Check if the stop signal is due to a breakpoint
                {
                    if (breakpoints_count != 0)
                    {
                        serve_breakpoint(elf, pid);
                        process_is_running = false;
                    }
                }
                else
                {
                    // Handle other stop signals
                    printf("HEREEEE\n");
                }
            }
            else
            {
                printf("HERE2\n");
            }
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
