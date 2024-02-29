#include <stdio.h>

int foo(void)
{
    printf("aaa\n");
    return 42;
}

int main(int argc, char *argv[])
{
    return foo();
}
