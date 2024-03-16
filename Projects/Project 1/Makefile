all:
	gcc elf_helpers.c cseas_elfloader.c -lelf -lcapstone -o cseas_elfloader
	gcc elfloader_example.c -o elfloader_example
clean:
	rm cseas_elfloader elfloader_example