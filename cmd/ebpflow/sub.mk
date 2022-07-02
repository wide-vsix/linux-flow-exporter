DEV1 := ens4
bpf-build:
	clang -target bpf -O3 -g -c cmd/ebpflow/filter.bpf.c -o cmd/ebpflow/filter.bpf.o
bpf-hotswap:
	clang -target bpf -O3 -g -c filter.bpf.c
	tc filter change dev $(DEV1) ingress pref 100 chain 0 handle 0x1 bpf obj filter.bpf.o section tc-ingress
