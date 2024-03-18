#include <stdio.h>
int ga = 42;
int ga2;
int ga3[10];
void foo(void)
{
    fprintf(stderr, "The value of the global variable is: %d.\n", ga);
}

int main(int argc, char *argv[])
{
    foo();
    return 1;
}