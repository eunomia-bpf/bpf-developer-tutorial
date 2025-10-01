// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#ifndef __COMMON_H
#define __COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include "blazesym.h"

/* Types needed for both profile and offcputime */
#define TASK_COMM_LEN		16
#define MAX_PID_NR		30
#define MAX_TID_NR		30


/* Common helper functions for BPF tools */

/**
 * split_convert - Split a string by a delimiter and convert each token
 * @s: String to split
 * @delim: Delimiter string
 * @elems: Array to store the converted elements
 * @elems_size: Size of the elems array in bytes
 * @elem_size: Size of each element in bytes
 * @convert: Function to convert each token to the desired type
 *
 * Return: 0 on success, negative error code on failure
 */
static inline int split_convert(char *s, const char* delim, void *elems, size_t elems_size,
                   size_t elem_size, int (*convert)(const char *, void *))
{
    char *token;
    int ret;
    char *pos = (char *)elems;

    if (!s || !delim || !elems)
        return -1;

    token = strtok(s, delim);
    while (token) {
        if (pos + elem_size > (char*)elems + elems_size)
            return -ENOBUFS;

        ret = convert(token, pos);
        if (ret)
            return ret;

        pos += elem_size;
        token = strtok(NULL, delim);
    }

    return 0;
}

/**
 * str_to_int - Convert a string to an integer
 * @src: Source string
 * @dest: Pointer to store the converted integer
 *
 * Return: 0 on success, negative error code on failure
 */
static inline int str_to_int(const char *src, void *dest)
{
    *(int*)dest = strtol(src, NULL, 10);
    return 0;
}

/**
 * show_stack_trace - Display a stack trace with symbol resolution
 * @symbolizer: Blazesym symbolizer instance
 * @stack: Array of stack addresses
 * @stack_sz: Size of the stack array
 * @pid: Process ID (0 for kernel)
 */
static void show_stack_trace(blaze_symbolizer *symbolizer, __u64 *stack, int stack_sz, pid_t pid)
{
    const struct blaze_syms *syms;
    int i;

    // Choose symbolization source based on pid
    if (pid) {
        const struct blaze_symbolize_src_process src = {
            .type_size = sizeof(src),
            .pid = pid,
        };
        syms = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uint64_t *)stack, stack_sz);
    } else {
        const struct blaze_symbolize_src_kernel src = {
            .type_size = sizeof(src),
            .kallsyms = NULL,
            .vmlinux = NULL,
            .debug_syms = false,
            .reserved = {0},
        };
        syms = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uint64_t *)stack, stack_sz);
    }

    if (!syms) {
        fprintf(stderr, "Failed to symbolize stack trace\n");
        return;
    }

    for (i = 0; i < stack_sz; i++) {
        if (!stack[i])
            continue;

        if (i >= syms->cnt) {
            printf("    [unknown]\n");
            continue;
        }

        const struct blaze_sym *sym = &syms->syms[i];
        if (sym->name) {
            printf("    %s\n", sym->name);
        } else {
            printf("    [unknown]\n");
        }
    }

    blaze_syms_free(syms);
}

/**
 * show_stack_trace_folded - Display a stack trace in folded format for flamegraphs
 * @symbolizer: Blazesym symbolizer instance
 * @stack: Array of stack addresses
 * @stack_sz: Size of the stack array
 * @pid: Process ID (0 for kernel)
 * @separator: Character to use as separator between frames (typically ';')
 * @reverse: Whether to print the stack in reverse order (true for flamegraphs)
 */
static void show_stack_trace_folded(blaze_symbolizer *symbolizer, __u64 *stack, int stack_sz,
                                    pid_t pid, char separator, bool reverse)
{
    const struct blaze_syms *syms;
    int i;
    bool first = true;

    // Choose symbolization source based on pid
    if (pid) {
        const struct blaze_symbolize_src_process src = {
            .type_size = sizeof(src),
            .pid = pid,
        };
        syms = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uint64_t *)stack, stack_sz);
    } else {
        const struct blaze_symbolize_src_kernel src = {
            .type_size = sizeof(src),
            .kallsyms = NULL,
            .vmlinux = NULL,
            .debug_syms = false,
            .reserved = {0},
        };
        syms = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uint64_t *)stack, stack_sz);
    }

    if (!syms) {
        fprintf(stderr, "Failed to symbolize stack trace\n");
        return;
    }

    /* For flamegraphs, we need to print the stack in reverse order */
    if (reverse) {
        for (i = stack_sz - 1; i >= 0; i--) {
            if (!stack[i])
                continue;

            if (i >= syms->cnt || !syms->syms[i].name) {
                if (!first) {
                    printf("%c", separator);
                }
                printf("[unknown]");
                first = false;
                continue;
            }

            const struct blaze_sym *sym = &syms->syms[i];
            if (!first) {
                printf("%c", separator);
            }
            printf("%s", sym->name);
            first = false;
        }
    } else {
        /* Print stack in normal order */
        for (i = 0; i < stack_sz; i++) {
            if (!stack[i])
                continue;

            if (i >= syms->cnt || !syms->syms[i].name) {
                if (!first) {
                    printf("%c", separator);
                }
                printf("[unknown]");
                first = false;
                continue;
            }

            const struct blaze_sym *sym = &syms->syms[i];
            if (!first) {
                printf("%c", separator);
            }
            printf("%s", sym->name);
            first = false;
        }
    }

    blaze_syms_free(syms);
}

/* Safe string duplication */
static inline char *safe_strdup(const char *s)
{
    char *ret = strdup(s);
    if (!ret) {
        fprintf(stderr, "failed to allocate memory\n");
        exit(1);
    }
    return ret;
}

#endif /* __COMMON_H */ 