# goroutine trace

**UNFINISHED YET**: The offset of goid field is hardcoded. It was only tested on the bundled `go-server-http`. It MAY NOT WORK on other go programs.

The bundled fo program was compiled using go 1.17.0. The executable and source could be found at folder `go-server-http`.

This example traces the state switch of goroutines, and prints the corresponding state, goid, pid and tgid.

```console
root@mnfe-pve:~/bpf-developer-tutorial/src/31-goroutine# ecc goroutine.bpf.c goroutine.h 
INFO [ecc_rs::bpf_compiler] Compiling bpf object...
INFO [ecc_rs::bpf_compiler] Generating export types...
INFO [ecc_rs::bpf_compiler] Generating package json..
INFO [ecc_rs::bpf_compiler] Packing ebpf object and config into package.json...
root@mnfe-pve:~/bpf-developer-tutorial/src/31-goroutine# ecli-rs run package.json 
INFO [faerie::elf] strtab: 0x6fb symtab 0x738 relocs 0x780 sh_offset 0x780
INFO [bpf_loader_lib::skeleton::preload::section_loader] User didn't specify custom value for variable __eunomia_dummy_goroutine_execute_data_ptr, use the default one in ELF
TIME     STATE  GOID   PID    TGID   
INFO [bpf_loader_lib::skeleton] Running ebpf program...
21:00:47  DEAD(6) 0    2542844 2542844
21:00:47  RUNNABLE(1) 0 2542844 2542844
21:00:47  DEAD(6) 0    2542844 2542844
21:00:47  RUNNING(2) 1 2542844 2542844
21:00:47  DEAD(6) 0    2542844 2542844
21:00:47  RUNNABLE(1) 0 2542844 2542844
21:00:47  RUNNABLE(1) 1 2542844 2542844
21:00:47  RUNNING(2) 2 2542847 2542844
21:00:47  WAITING(4) 2 2542847 2542844
....
```


This example is provided as GPL license
