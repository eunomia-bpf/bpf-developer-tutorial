#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <errno.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    char *btf_base_path = argv[1];
    char *btf_src_path = argv[2];
    char *btf_dst_path = argv[3];
    struct btf *btf_src, *btf_base;
    int err;
    unsigned int size;
    const void* btf_data;
    FILE *fp;


    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s <btf_base> <btf_src> <btf_dst>\n", argv[0]);
        fprintf(stderr, "Used for merge btf info");
        return 1;
    }

    btf_base = btf__parse(btf_base_path, NULL);
    if (!btf_base)
    {
        fprintf(stderr, "Failed to parse BTF object '%s': %s\n", btf_base_path, strerror(errno));
        return 1;
    }

    btf_src = btf__parse(btf_src_path, NULL);
    if (!btf_src)
    {
        fprintf(stderr, "Failed to parse BTF object '%s': %s\n", btf_src_path, strerror(errno));
        return 1;
    }

    err = btf__add_btf(btf_base, btf_src);
    if (err < 0)
    {
        fprintf(stderr, "Failed to add BTF object '%s': %s\n", btf_src_path, strerror(errno));
        return 1;
    }

    btf_data = btf__raw_data(btf_base, &size);
    if (!btf_data)
    {
        fprintf(stderr, "Failed to get raw data of BTF object '%s': %s\n", btf_base_path, strerror(errno));
        return 1;
    }
    fp = fopen(btf_dst_path, "w");
    if (!fp)
    {
        fprintf(stderr, "Failed to open BTF object '%s': %s\n", btf_dst_path, strerror(errno));
        return 1;
    }
    fwrite(btf_data, size, 1, fp);
    fclose(fp);

    return 0;
}