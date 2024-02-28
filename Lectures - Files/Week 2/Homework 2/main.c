void foo(void); /* Implemented in a shared library. */
int main(int argc, char *argv[]) {
foo(); /* 1st call. */
foo(); /* 2nd call. */
return 1;
}
