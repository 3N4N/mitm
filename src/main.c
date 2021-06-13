#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "errmsg.h"

int main(int argc, char *argv[])
{
    if (argc != 4) {
        fprintf(stderr, ERROR_DISPLAY_USAGE, argv[0]);
        exit(EXIT_FAILURE);
    }
    return 0;
}

