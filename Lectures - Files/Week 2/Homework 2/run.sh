#!/bin/bash

gcc -Wall foo.c -shared -fPIC -o libfoo.so
# compile the main program
gcc -Wall main.c -L. -lfoo -o main
# update the path for the dynamic linker to find libfoo.so
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:.
# run
./main
