#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

// This is the original function to hook.
void my_function()
{
    printf("Hello, world!\n");
}

int main()
{
    my_function();

    return 0;
}
