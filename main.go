package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const bpfPath = "bpf/sigsnoop.o"

func main() {
	spec, err := ebpf.LoadCollectionSpec(bpfPath)
	if err != nil {
		log.Fatalf("Failed to load collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to load collection: %v", err)
	}
	defer coll.Close()

	kill_entry, ok := coll.Programs["kill_entry"]
	if !ok {
		log.Fatalf("Failed to find kill_entry in ELF")
	}

	kill_exit, ok := coll.Programs["kill_exit"]
	if !ok {
		log.Fatalf("Failed to find kill_exit in ELF")
	}

	ken, err := link.Tracepoint("syscalls", "sys_enter_kill", kill_entry, nil)
	if err != nil {
		log.Fatalf("Failed to attach kill_entry: %v", err)
	}
	defer ken.Close()

	kex, err := link.Tracepoint("syscalls", "sys_exit_kill", kill_exit, nil)
	if err != nil {
		log.Fatalf("Failed to attach kill_exit: %v", err)
	}
	defer kex.Close()

	fmt.Println("ebpf program loaded successfully......")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("Exiting and detaching............")
}
