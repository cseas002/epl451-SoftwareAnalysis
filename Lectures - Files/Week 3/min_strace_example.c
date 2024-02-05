
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char *argv[]) {

  	fprintf(stderr, "My pid is: %d.\n", getpid());

	return 1;
}
