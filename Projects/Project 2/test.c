#include <stdio.h>

int foo(int arg)
{
    if (arg == 1)
        return 0;
    return foo(arg - 1);
}

int main(int argc, char *argv[])
{

    foo(2);
    fprintf(stderr, "Hello World.\n");
    return 1;
}
