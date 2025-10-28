// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Python Thread State Discovery
 * Finds PyThreadState addresses for Python processes
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>
#include <elf.h>
#include <fcntl.h>

#define MAX_LINE 1024
#define MAX_PATH 256

struct memory_region {
	unsigned long start;
	unsigned long end;
	char perms[5];
	char path[MAX_PATH];
};

// Read /proc/<pid>/maps to find libpython
static int find_libpython_base(pid_t pid, unsigned long *base_addr, char *libpython_path)
{
	char maps_path[64];
	FILE *fp;
	char line[MAX_LINE];
	int found = 0;

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	fp = fopen(maps_path, "r");
	if (!fp) {
		fprintf(stderr, "Failed to open %s: %s\n", maps_path, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		unsigned long start, end;
		char perms[5], path[MAX_PATH];

		// Parse: address-address perms offset dev inode pathname
		if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %s",
			   &start, &end, perms, path) < 3) {
			continue;
		}

		// Look for libpython3.x.so
		if (strstr(path, "libpython3") && strstr(path, ".so")) {
			// We want the first executable mapping
			if (strchr(perms, 'x') && !found) {
				*base_addr = start;
				strncpy(libpython_path, path, MAX_PATH - 1);
				libpython_path[MAX_PATH - 1] = '\0';
				found = 1;
				break;
			}
		}
	}

	fclose(fp);

	if (!found) {
		fprintf(stderr, "libpython not found in process %d\n", pid);
		return -1;
	}

	return 0;
}

// Simple ELF parser to find symbol offset
static int find_symbol_offset(const char *elf_path, const char *symbol_name,
			      unsigned long *offset)
{
	int fd;
	Elf64_Ehdr ehdr;
	Elf64_Shdr *shdrs = NULL;
	Elf64_Sym *symtab = NULL;
	char *strtab = NULL;
	int ret = -1;
	size_t i, j;

	fd = open(elf_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n", elf_path, strerror(errno));
		return -1;
	}

	// Read ELF header
	if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
		fprintf(stderr, "Failed to read ELF header\n");
		goto cleanup;
	}

	// Verify ELF magic
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stderr, "Not a valid ELF file\n");
		goto cleanup;
	}

	// Read section headers
	shdrs = malloc(ehdr.e_shentsize * ehdr.e_shnum);
	if (!shdrs) {
		fprintf(stderr, "Failed to allocate memory\n");
		goto cleanup;
	}

	lseek(fd, ehdr.e_shoff, SEEK_SET);
	if (read(fd, shdrs, ehdr.e_shentsize * ehdr.e_shnum) !=
	    ehdr.e_shentsize * ehdr.e_shnum) {
		fprintf(stderr, "Failed to read section headers\n");
		goto cleanup;
	}

	// Find .symtab and .strtab
	for (i = 0; i < ehdr.e_shnum; i++) {
		if (shdrs[i].sh_type == SHT_DYNSYM || shdrs[i].sh_type == SHT_SYMTAB) {
			// Read symbol table
			symtab = malloc(shdrs[i].sh_size);
			if (!symtab)
				goto cleanup;

			lseek(fd, shdrs[i].sh_offset, SEEK_SET);
			if (read(fd, symtab, shdrs[i].sh_size) != (ssize_t)shdrs[i].sh_size)
				goto cleanup;

			// Find associated string table
			Elf64_Shdr *strtab_shdr = &shdrs[shdrs[i].sh_link];
			strtab = malloc(strtab_shdr->sh_size);
			if (!strtab)
				goto cleanup;

			lseek(fd, strtab_shdr->sh_offset, SEEK_SET);
			if (read(fd, strtab, strtab_shdr->sh_size) != (ssize_t)strtab_shdr->sh_size)
				goto cleanup;

			// Search for symbol
			size_t num_symbols = shdrs[i].sh_size / sizeof(Elf64_Sym);
			for (j = 0; j < num_symbols; j++) {
				const char *name = strtab + symtab[j].st_name;
				if (strcmp(name, symbol_name) == 0) {
					*offset = symtab[j].st_value;
					ret = 0;
					goto cleanup;
				}
			}

			free(symtab);
			free(strtab);
			symtab = NULL;
			strtab = NULL;
		}
	}

cleanup:
	if (shdrs)
		free(shdrs);
	if (symtab)
		free(symtab);
	if (strtab)
		free(strtab);
	close(fd);
	return ret;
}

// Read memory from process using /proc/<pid>/mem
static int read_process_memory(pid_t pid, unsigned long addr, void *buf, size_t size)
{
	char mem_path[64];
	int fd;
	ssize_t bytes_read;

	snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
	fd = open(mem_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open %s: %s\n", mem_path, strerror(errno));
		return -1;
	}

	if (lseek(fd, addr, SEEK_SET) == (off_t)-1) {
		fprintf(stderr, "Failed to seek to 0x%lx: %s\n", addr, strerror(errno));
		close(fd);
		return -1;
	}

	bytes_read = read(fd, buf, size);
	close(fd);

	if (bytes_read != (ssize_t)size) {
		fprintf(stderr, "Failed to read %zu bytes at 0x%lx: %s\n",
			size, addr, strerror(errno));
		return -1;
	}

	return 0;
}

int discover_python_thread_states(pid_t pid)
{
	unsigned long libpython_base;
	char libpython_path[MAX_PATH];
	unsigned long symbol_offset;
	unsigned long symbol_addr;
	unsigned long runtime_addr;
	unsigned long gilstate_addr;
	unsigned long tstate_addr;

	printf("Discovering Python thread states for PID %d...\n", pid);

	// Step 1: Find libpython base address
	if (find_libpython_base(pid, &libpython_base, libpython_path) < 0) {
		return -1;
	}
	printf("Found libpython at 0x%lx: %s\n", libpython_base, libpython_path);

	// Step 2: Find _PyRuntime symbol (Python 3.7+)
	if (find_symbol_offset(libpython_path, "_PyRuntime", &symbol_offset) == 0) {
		symbol_addr = libpython_base + symbol_offset;
		printf("Found _PyRuntime symbol at offset 0x%lx (absolute: 0x%lx)\n",
		       symbol_offset, symbol_addr);

		// Read _PyRuntime address
		if (read_process_memory(pid, symbol_addr, &runtime_addr, sizeof(runtime_addr)) == 0) {
			printf("_PyRuntime data at 0x%lx\n", runtime_addr);

			// For Python 3.7+: _PyRuntime.gilstate.tstate_current
			// Offset varies by Python version, typically around +8 bytes for gilstate
			// then another offset for tstate_current
			// This is a simplified approach - real implementation needs version detection
			gilstate_addr = symbol_addr + 232; // Approximate offset for Python 3.8+

			if (read_process_memory(pid, gilstate_addr, &tstate_addr, sizeof(tstate_addr)) == 0) {
				printf("Current thread state pointer: 0x%lx\n", tstate_addr);
				return 0;
			}
		}
	}

	// Fallback: Try interp_head (older Python versions)
	if (find_symbol_offset(libpython_path, "interp_head", &symbol_offset) == 0) {
		symbol_addr = libpython_base + symbol_offset;
		printf("Found interp_head symbol at offset 0x%lx (absolute: 0x%lx)\n",
		       symbol_offset, symbol_addr);

		// Read interp_head pointer
		unsigned long interp_addr;
		if (read_process_memory(pid, symbol_addr, &interp_addr, sizeof(interp_addr)) == 0) {
			printf("Interpreter head at 0x%lx\n", interp_addr);
			// Would need to walk interpreter threads from here
			return 0;
		}
	}

	fprintf(stderr, "Failed to find Python runtime symbols\n");
	return -1;
}

int main(int argc, char **argv)
{
	pid_t pid;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
		return 1;
	}

	pid = atoi(argv[1]);
	if (pid <= 0) {
		fprintf(stderr, "Invalid PID\n");
		return 1;
	}

	return discover_python_thread_states(pid);
}
