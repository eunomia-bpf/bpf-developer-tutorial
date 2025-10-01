// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Test program for memleak - intentionally leaks memory for testing
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

void leak_small() {
    malloc(1024);
}

void leak_large() {
    malloc(8192);
}

void leak_with_loop() {
    for (int i = 0; i < 5; i++) {
        malloc(2048);
    }
}

int main() {
    printf("Memory leak test starting (PID: %d)\n", getpid());
    printf("This program intentionally leaks memory for testing memleak\n");

    // Wait a bit for memleak to attach
    sleep(2);

    // Create various leaks
    leak_small();
    sleep(1);

    leak_large();
    sleep(1);

    leak_with_loop();
    sleep(1);

    // Keep running so memleak can observe
    printf("Leaks created, sleeping for 30 seconds...\n");
    sleep(30);

    printf("Test complete\n");
    return 0;
}
