package capture

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FilterOptions represents the filtering criteria.
type FilterOptions struct {
	Protocol      string   // e.g., "tcp", "udp", "icmp"
	SourceIP      string   // Specific source IP to filter
	DestinationIP string   // Specific destination IP to filter
	Ports         []uint16 // List of ports to filter
}

// FilterPacket determines whether a packet matches the filter options.
func FilterPacket(packet gopacket.Packet, options FilterOptions) bool {
	// Ensure the packet contains the Network Layer
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return false
	}

	// Check source and destination IPs if specified
	if options.SourceIP != "" && networkLayer.NetworkFlow().Src().String() != options.SourceIP {
		return false
	}
	if options.DestinationIP != "" && networkLayer.NetworkFlow().Dst().String() != options.DestinationIP {
		return false
	}

	// Check transport layer for protocol and port filtering
	transportLayer := packet.TransportLayer()
	if transportLayer != nil {
		switch options.Protocol {
		case "tcp":
			if _, ok := transportLayer.(*layers.TCP); !ok {
				return false
			}
		case "udp":
			if _, ok := transportLayer.(*layers.UDP); !ok {
				return false
			}
		case "icmp":
			if packet.Layer(layers.LayerTypeICMPv4) == nil {
				return false
			}
		}

		// If port filtering is enabled
		if len(options.Ports) > 0 {
			portMatched := false
			if tcp, ok := transportLayer.(*layers.TCP); ok {
				portMatched = matchPort(uint16(tcp.SrcPort), uint16(tcp.DstPort), options.Ports)

			} else if udp, ok := transportLayer.(*layers.UDP); ok {
				portMatched = matchPort(uint16(udp.SrcPort), uint16(udp.DstPort), options.Ports)
			}
			if !portMatched {
				return false
			}
		}
	}

	return true
}

// matchPort checks if any port in the list matches the source or destination port.
func matchPort(srcPort, dstPort uint16, ports []uint16) bool {
	for _, port := range ports {
		if uint16(srcPort) == port || uint16(dstPort) == port {
			return true
		}
	}
	return false
}

// PrintFilteredPacket prints packet information if it matches the filter options.
func PrintFilteredPacket(packet gopacket.Packet, options FilterOptions) {
	if FilterPacket(packet, options) {
		fmt.Printf("Filtered Packet:\n%s\n", packet)
	}
}
