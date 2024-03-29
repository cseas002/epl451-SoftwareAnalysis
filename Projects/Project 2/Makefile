all:
	gcc -Wall elf_mdb_helpers.c mdb.c -lelf -lcapstone -o mdb
	gcc -Wall test.c -no-pie -o test
clean:
	rm cseas_elfloader elfloader_example