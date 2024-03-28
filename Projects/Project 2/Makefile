all:
	gcc elf_mdb_helpers.c mdb.c -lelf -lcapstone -o mdb
	gcc test.c -o test
clean:
	rm cseas_elfloader elfloader_example