package ebpf

// Guarded until Task 8 introduces ../../bpf/egress.c.
//go:generate sh -c 'test -f ../../bpf/egress.c && go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g" bpf ../../bpf/egress.c -- -I../../bpf/include || echo "skip bpf2go: ../../bpf/egress.c missing"'
