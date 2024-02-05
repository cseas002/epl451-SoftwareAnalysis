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

#define die(...) \
    do { \
        fprintf(stderr, "min_strace: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

int main(int argc, char **argv)
{
    if (argc <= 1)
        die("min_strace <program>: %d", argc);

    /* fork() for executing the program that is analyzed.  */
    pid_t pid = fork();
    switch (pid) {
        case -1: /* error */
            die("%s", strerror(errno));
        case 0:  /* Code that is run by the child. */
            /* Start tracing.  */
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            /* execvp() is a system call, the child will block and
               the parent must do waitpid().
               The waitpid() of the parent is in the label
               waitpid_for_execvp.
             */
            execvp(argv[1], argv + 1);
            die("%s", strerror(errno));
    }

    /* Code that is run by the parent.  */

    /* We need to waitpid() for the execvp() in the child.  */
    waitpid_for_execvp:
    waitpid(pid, 0, 0); 
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

    while (1) {
        /* Enter next system call.
           It can be the entrance or the exit of the system call. 
          */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            die("%s", strerror(errno));
        /* Block until process state change (i.e., next event). */
        if (waitpid(pid, 0, 0) == -1)
            die("%s", strerror(errno));  

        /* Collect information about the system call.  */
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            if (errno == ESRCH) {
                /* System call was exit; so we need to end.  */
                fprintf(stderr, "\n");
                exit(regs.rdi); 
            }
            die("%s", strerror(errno));
        }

        if (regs.rax == -ENOSYS) {
            /* We are in the system call's entrance. */
            long syscall = regs.orig_rax;
        
            /* Output the system call. */
            fprintf(stderr, "%ld(%ld, %ld, %ld, %ld, %ld, %ld)",
                syscall,
                (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
                (long)regs.r10, (long)regs.r8,  (long)regs.r9);
    
            } else
                /* We are in the system call's exit. */
                fprintf(stderr, " = %ld\n", (long)regs.rax);
    
        }
}
