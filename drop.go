package main

import (
	"C"
	"fmt"
	"strconv"
	"syscall"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
)

import (
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

const (
	TYPE_ENTER = 1
	TYPE_DROP  = 2
	TYPE_PASS  = 3
)

func main() {
	// sig := make(chan os.Signal, 1)
	// signal.Notify(sig, os.Interrupt)
	// Remove MEMLOCK resource limit
	if err := rlimit.RemoveMemlock(); err != nil {
		// Handle error
		fmt.Printf("Failed to remove MEMLOCK limit: %v\n", err)
	}

	if len(os.Args) < 2 {
		fmt.Println("please provide the network interface")
		return
	}

	iface := os.Args[1]
	allowedPort := os.Args[2]

	// Parse the allowed port argument
	allowedPortInt, err := strconv.Atoi(allowedPort)
	if err != nil {
		fmt.Printf("Invalid allowed port: %v\n", err)
		return
	}


	spec, err := ebpf.LoadCollectionSpec("dropipv4.o")
	if err != nil {
		panic(err)
	}
	coll, _ := ebpf.NewCollection(spec)
	if err != nil {
		panic(fmt.Sprintf("Failed to create new collection: %v\n", err))
	}
	if err != nil {
		panic(fmt.Sprintf("Failed to update map: %v\n", err))
	}
	defer coll.Close()
	prog := coll.Programs["drop_packets"]
	if prog == nil {
		panic("No program named 'capture_packets' found in collection")
	}

	iface_idx, err := net.InterfaceByName(iface)
	if err != nil {
		panic(fmt.Sprintf("Failed to get interface %s: %v\n", iface, err))
	}
	opts := link.XDPOptions{
		Program:   prog,
		Interface: iface_idx.Index,
		// Flags is one of XDPAttachFlags (optional).
	}
	lnk, err := link.AttachXDP(opts)
	if err != nil {
		panic(err)
	}
	
	var lookupKey uint32 = 0
	var portNum uint16 = uint16(allowedPortInt)
	portMap, ok := coll.Maps["port"]
	if !ok {
		panic("No map named 'port'")
	}
	err = portMap.Update(lookupKey, portNum, ebpf.UpdateAny)
	if err != nil {
		panic(fmt.Sprintf("Could not update port map %v", err))
	}
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	var packets_dropped []uint16

	fmt.Println("Successfully loaded and attached BPF program.")
	fmt.Println("Press Ctrl+c to end detach the program")


	go func() {
		for range ticker.C {
			err := coll.Maps["rxcnt"].Lookup(lookupKey, &packets_dropped)
			if err != nil {
				panic(fmt.Sprintf("Could not lookup rxcnt %v", err))
			}
			var total_dropped uint16 = 0
			for _, cpuvalue := range packets_dropped {
				total_dropped += cpuvalue
			}
	
			log.Info("Dropped packets:", total_dropped)
		}
	}()
	defer lnk.Close()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	
}