package main

import (
	"log"
	"traffic-sniffer/pkg/capture"

	"github.com/google/gopacket/pcap"
)

func scanDevices() []pcap.Interface {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error finding devices: %v", err)
	}

	// fmt.Println("Devices found:")
	// for _, device := range devices {
	// 	fmt.Printf("Name: %s, Description: %s\n", device.Name, device.Description)
	// 	for _, address := range device.Addresses {
	// 		fmt.Printf("  IP address: %s, Subnet mask: %s\n", address.IP, address.Netmask)
	// 	}
	// }
	return devices
}

func main() {
	devices := scanDevices()

	err := capture.StartSniffer(devices[1].Name)
	if err != nil {
		log.Fatalf("Error starting sniffer: %v", err)
	}
}
