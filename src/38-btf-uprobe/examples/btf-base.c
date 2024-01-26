#include <stdio.h>

// use a different struct
struct data {
        int a;
        int c;
        int d;
};

int add_test(struct data *d) {
    return d->a + d->c;
}

int main(int argc, char **argv) {
    struct data d = {1, 3, 4};
    printf("add_test(&d) = %d\n", add_test(&d));
    return 0;
}

