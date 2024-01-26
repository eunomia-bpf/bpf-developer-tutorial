#include <stdio.h>

struct data {
        int a;
        int b;
        int c;
        int d;
};

int add_test(struct data *d) {
    return d->a + d->c;
}

int main(int argc, char **argv) {
    struct data d = {1, 2, 3, 4};
    printf("add_test(&d) = %d\n", add_test(&d));
    return 0;
}

