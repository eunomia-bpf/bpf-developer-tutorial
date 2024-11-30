# xdp-pktgen: xdp based packet generator

This is a simple xdp based packet generator.

## **How to use**

clone the repo, you can update the git submodule with following commands:

```sh
git submodule update --init --recursive
```

### **3. Install dependencies**

For dependencies, it varies from distribution to distribution. You can refer to shell.nix and dockerfile for installation.

On Ubuntu, you may run `make install` or

```sh
sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev \
        make clang llvm
```

to install dependencies.

### **4. Build the project**

To build the project, run the following command:

```sh
make build
```

This will compile your code and create the necessary binaries. You can you the `Github Code space` or `Github Action` to build the project as well.

### ***Run the Project***

You can run the binary with:

```console
sudo ./xdp-pktgen
```

