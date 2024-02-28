
#include <stdlib.h>

int main(int argc, char *argv[]) {

    for (int i = 0; i < 1028; i++) {
        void *p = malloc(16);

        if (i % 2) free(p);
    }

	return 1;
}
