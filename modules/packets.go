/*
Copyright 2024 Georgia Institute of Technology

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package modules

import (
	"math/rand"

	"github.com/google/gopacket/layers"
)

// MakeEthHeader returns ethernet layer part of the packet
func MakeEthHeader(etherType layers.EthernetType) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       conf.IFace.HardwareAddr,
		DstMAC:       conf.Gateway,
		EthernetType: etherType,
	}
}

// MakeIPHeader returns IP layer part of the packet. It supports
// both IPv4 and IPv6.
func MakeIPHeader(protocol layers.IPProtocol) interface{} {
	// DstIP should be set by the MakePacket calls
	if conf.IsIPv4 {
		return &layers.IPv4{
			SrcIP:    conf.SrcIP,
			Version:  4,
			Protocol: protocol,
			TTL:      64, // MaxTTL = 255
		}
	} else {
		return &layers.IPv6{
			SrcIP:      conf.SrcIP,
			Version:    6,
			NextHeader: protocol,
			HopLimit:   64, // MaxHopLimit = 255
		}
	}
}

// MakeIP6Header returns IP layer part of an IPv6 packet.
func MakeIP6Header(protocol layers.IPProtocol) *layers.IPv6 {
	// DstIP should be set by the MakePacket calls
	return &layers.IPv6{
		SrcIP:      conf.SrcIP,
		Version:    6,
		NextHeader: protocol,
		HopLimit:   64, // MaxHopLimit = 255
	}
}

// MakeICMP6Header returns an ICMP6 layer
func MakeICMP6Header() *layers.ICMPv6 {
	return &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(128, 0),
	}
}

// MakeICMP6EchoHeader returns the header for an
// ICMP6 Echo Packet
func MakeICMP6EchoHeader() *layers.ICMPv6Echo {
	return &layers.ICMPv6Echo{
		Identifier: 0,
		SeqNumber:  0,
	}
}

// MakeUDPHeader returns the header for a UDP packet
// with the given destination port.
func MakeUDPHeader(dstPort int) *layers.UDP {
	return &layers.UDP{
		DstPort: layers.UDPPort(dstPort),
	}
}

// MakeDNSHeader returns the correctly initialized
// DNS headers with the given DNS ID, Question
// and DNS packet type.
func MakeDNSHeader(dnsID int, question string, typ layers.DNSType) *layers.DNS {
	dns := &layers.DNS{
		ID:     uint16(dnsID),
		OpCode: layers.DNSOpCodeQuery,
		RD:     true,
	}
	dns.Questions = append(dns.Questions,
		layers.DNSQuestion{
			Name:  []byte(question),
			Type:  typ,
			Class: layers.DNSClassIN,
		})
	return dns
}

// MakeTCPSynHeader returns a TCP SYN packet header.
func MakeTCPSynHeader() *layers.TCP {
	return &layers.TCP{
		Seq:        rand.Uint32(),
		Ack:        0,
		Checksum:   0,
		SYN:        true,
		DstPort:    layers.TCPPort(conf.TargetPort),
		Window:     65535,
		DataOffset: 5,
		Urgent:     0,
	}
}
