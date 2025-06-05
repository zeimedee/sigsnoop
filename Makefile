compile:
	clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 -I. -c bpf/sigsnoop.c -o bpf/sigsnoop.o
