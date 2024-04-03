all:
	gcc -Wall elf_mdb_helpers.c mdb.c -lelf -lcapstone -o mdb
	gcc -Wall test.c -o test -no-pie
clean:
	rm mdb test