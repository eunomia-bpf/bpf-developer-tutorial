#include <stdio.h>
#include <stdlib.h>

struct deep_memory_block {
    int a;
    char b[10];
};

struct inner_memory_block {
    int a;
    char b[10];
    struct deep_memory_block *deep;
};

struct data {
        int a;
        int b;
        int c;
        int d;
        // represent a pointer to a memory block
        struct inner_memory_block *inner;
};

// hook function to be called by eBPF program
int add_test(struct data *d) {
    return d->a + d->c;
}

struct data* my_alloc_data() {
    printf("my_alloc_data\n");
    struct data *d = (struct data*)calloc(1, sizeof(struct data));
    d->inner = (struct inner_memory_block*)calloc(1, sizeof(struct inner_memory_block));
    d->inner->deep = (struct deep_memory_block*)calloc(1, sizeof(struct deep_memory_block));
    return d;
}

void my_free_data(struct data *d) {
    printf("my_free_data\n");
    free(d->inner->deep);
    free(d->inner);
    free(d);
}

int main(int argc, char **argv) {
    struct data *d = my_alloc_data();
    d->a = 1;
    d->c = 3;
    d->b = 5;
    d->d = 7;
    printf("add_test(&d) = %d\n", add_test(d));
    my_free_data(d);
    return 0;
}

