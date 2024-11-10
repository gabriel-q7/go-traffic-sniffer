package main

import (
	"fmt"
	"log"
	"traffic-sniffer/pkg/capture"

	"github.com/google/gopacket/pcap"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error finding devices: %v", err)
	}

	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Printf("Name: %s, Description: %s\n", device.Name, device.Description)
		for _, address := range device.Addresses {
			fmt.Printf("  IP address: %s, Subnet mask: %s\n", address.IP, address.Netmask)
		}
	}

	err2 := capture.StartSniffer("en0")
	if err2 != nil {
		log.Fatalf("Error starting sniffer: %v", err2)
	}
}
