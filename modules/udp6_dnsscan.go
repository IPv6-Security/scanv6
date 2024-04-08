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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
)

// Module specific flags.
type UDPDNSScanFlags struct {
	Domain       string `long:"udp-query-domain" default:"akamai.com" description:"The domain name used for the UDP query"`
	UDPQueryType string `long:"udp-query-type" choice:"A" choice:"TXT" choice:"AAAA" default:"A" description:"The query type used for the UDP query"`
}

// Module Scanner Instance. It holds the pcap filter
// objects to parse each network packet layer into
// parser object, and the module specific flags.
type UDPDNSScanModule struct {
	PcapFilter              string
	ethHdr                  *layers.Ethernet
	ip6Hdr                  *layers.IPv6
	udpHdr                  *layers.UDP
	dnsHdr                  *layers.DNS
	parser                  *ModulePacketParser
	icmpv6DestUnreachParser *ICMPv6DestUnreachParser
	Flags                   *UDPDNSScanFlags
}

// Struct object to wrap around a DNS Answer
type dnsAnswer struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

// Output object for detailed output
type dnsOutput struct {
	Resolver        string      `json:"saddr"`
	IP              string      `json:"daddr"`
	SrcPort         uint16      `json:"srcPort"`
	DstPort         uint16      `json:"dstPort"`
	IPFlowLabel     uint32      `json:"ip_flow_label"`
	IPFlowLabelSent uint32      `json:"ip_flow_label_sent"`
	IPHopLimit      uint8       `json:"ip_hop_limit"`
	IPTrafficClass  uint8       `json:"ip_traffic_class"`
	ProbeNum        int         `json:"probe_num"`
	DNSQueryType    string      `json:"dns_query_type"`
	Success         bool        `json:"success"`
	Domain          string      `json:"domain"`
	Answers         []dnsAnswer `json:"answers"`
	NS              []string    `json:"ns"`
	Questions       []string    `json:"questions"`
	TTL             uint8       `json:"ttl"`
	DNSID           uint16      `json:"dnsid"`
	Status          string      `json:"status"`
	Timestamp       int64       `json:"timestamp_ns"`
}

// Output object for ICMPv6 Destination Unreachable output
type DNSInICMPv6DestUnreachOutput struct {
	SrcIP            string   `json:"saddr"`
	DstIP            string   `json:"daddr"`
	TargetIP         string   `json:"taddr"`
	IPFlowLabel      uint32   `json:"ip_flow_label"`
	SentFlowLabel    uint32   `json:"sent_ip_flow_label"`
	IPHopLimit       uint8    `json:"ip_hop_limit"`
	InIPHopLimit     uint8    `json:"inner_ip_hop_limit"`
	IPTrafficClass   uint8    `json:"ip_traffic_class"`
	Type             uint8    `json:"type"`
	Code             uint8    `json:"code"`
	SentSrcPort      uint16   `json:"sent_srcPort"`
	SentDstPort      uint16   `json:"sent_dstPort"`
	SentDNSQueryType string   `json:"sent_dns_query_type"`
	SentDomain       string   `json:"sent_domain"`
	SentQuestions    []string `json:"sent_questions"`
	SentDNSID        uint16   `json:"sent_dnsid"`
	Timestamp        int64    `json:"timestamp_ns"`
}

// init function registers the module into the scanner program.
func init() {
	RegisterUDPDnsModule()
}

// RegisterUDPDnsModule adds this module to the list of
// available modules with the summary information, a function
// to create a fresh scanner module object and module
// specific flags object for this module.
func RegisterUDPDnsModule() {
	AVAILABLE_MODULES = append(AVAILABLE_MODULES, ModuleEntry{
		ModuleName:   "udp6_dnsscan",
		ShortDesc:    "IPv6 UDP DNS Scan",
		LongDesc:     "This module sends out IPv6 DNS queries and parses basic responses.",
		CreateModule: func() (Module, int) { return new(UDPDNSScanModule), 6 },
		Flags:        new(UDPDNSScanFlags),
	})
}

// ValidateFlags validates module specific flags if there is any.
// It should raise a FATAL error if the validation fails.
func (sf *UDPDNSScanFlags) ValidateFlags() {
}

// ValidateFlags is a wrapper to call validation function for
// module specific flags
func (scanner *UDPDNSScanModule) ValidateFlags() {
	scanner.Flags.ValidateFlags()
}

// SetFlags deep copies the given module specific object to
// module's flag object
func (scanner *UDPDNSScanModule) SetFlags(val ModuleFlags) {
	scanner.Flags = GetDeepCopyModuleFlags(val).(*UDPDNSScanFlags)
}

// Init initializes the scanner module. This is generally
// used for setting the pcap filter with the correct
// IP address (source IP of the scanner).
func (scanner *UDPDNSScanModule) Init() {
	if conf.IsIPv4 {
		scanner.PcapFilter = fmt.Sprintf("((udp) && ip dst host %s)", conf.SourceAddress)
	} else {
		scanner.PcapFilter = fmt.Sprintf("((ip6 proto 17 || (icmp6 && (ip6[40] == 1))) && ip6 dst host %s)", conf.SourceAddress)
	}
}

// ThreadInit does the thread specific initilizations (related to
// pointers and parsers).
func (scanner *UDPDNSScanModule) ThreadInit() {
	scanner.ethHdr = MakeEthHeader(layers.EthernetTypeIPv6)
	scanner.ip6Hdr = MakeIP6Header(layers.IPProtocolUDP)
	scanner.udpHdr = MakeUDPHeader(53)
	if scanner.Flags.UDPQueryType == "A" {
		scanner.dnsHdr = MakeDNSHeader(0, scanner.Flags.Domain, layers.DNSTypeA)
	} else if scanner.Flags.UDPQueryType == "TXT" {
		scanner.dnsHdr = MakeDNSHeader(0, scanner.Flags.Domain, layers.DNSTypeTXT)
	} else if scanner.Flags.UDPQueryType == "AAAA" {
		scanner.dnsHdr = MakeDNSHeader(0, scanner.Flags.Domain, layers.DNSTypeAAAA)
	}

	scanner.parser = MakeNewModulePacketParser()
	scanner.parser.Parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, scanner.parser.ETH, scanner.parser.IP6, scanner.parser.ICMPv6, scanner.parser.UDP, scanner.parser.DNS, &scanner.parser.Payload)
	scanner.parser.Parser.IgnoreUnsupported = true // avoid `No decoder for layer type ICMPv6RouterAdvertisement` error

	scanner.icmpv6DestUnreachParser = MakeNewICMPv6DestUnreachableParser()
	if conf.ICMPDestUnreachableOutput != "" {
		scanner.icmpv6DestUnreachParser.Parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6,
			scanner.icmpv6DestUnreachParser.IP6, scanner.icmpv6DestUnreachParser.UDP, scanner.icmpv6DestUnreachParser.DNS,
			&scanner.icmpv6DestUnreachParser.Payload)
		scanner.icmpv6DestUnreachParser.Parser.IgnoreUnsupported = true
	}
}

// MakePacket compiles a network packet based on the module specifications.
// It needs to embed validation bits to some part of the packet
// to enable scanner verify whether the responses belong to the
// scan activity or not.
func (scanner *UDPDNSScanModule) MakePacket(probeNum int, dstIP net.IP, validation []byte) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// embed the validation bits to DNS ID field
	dnsID := binary.BigEndian.Uint16(validation[:2])
	scanner.dnsHdr.ID = dnsID

	// embed the port number
	scanner.udpHdr.SrcPort = layers.UDPPort(GetSourcePort(int(numOfSrcPorts), probeNum, validation))

	// set the target IP
	scanner.ip6Hdr.DstIP = dstIP

	// set a random flowLabel
	flowLabel := binary.BigEndian.Uint32(validation[8:12])
	scanner.ip6Hdr.FlowLabel = flowLabel & 0x000FFFFF

	// calculate the checksums and create the packet
	err := scanner.udpHdr.SetNetworkLayerForChecksum(scanner.ip6Hdr)
	if err != nil {
		log.Fatalf("error while setting the network later for checksum: %s", err)
	}
	if err := gopacket.SerializeLayers(buf, opts, scanner.ethHdr, scanner.ip6Hdr, scanner.udpHdr, scanner.dnsHdr); err != nil {
		log.Error(err)
	}
	return buf.Bytes()
}

// PrintPacket creates a string representation of the packet
// for dry-run mode.
func (scanner *UDPDNSScanModule) PrintPacket() {
	// TODO: for dry-run
}

// Name returns the name of the module
func (scanner *UDPDNSScanModule) Name() string {
	return "udp6_dnsscan"
}

// ValidatePacket validates the received network packet according to
// module specifications. It may or may not use the validation
// bits as well as destination IP (target IP).
func (scanner *UDPDNSScanModule) ValidatePacket(data []byte, srcIP net.IP, dstIP net.IP,
	validation []byte, recvTime time.Time, icmpDestUnreachOutputChan chan string) bool {
	if scanner.parser.IP6.NextHeader != layers.IPProtocolUDP {
		if scanner.parser.IP6.NextHeader == layers.IPProtocolICMPv6 &&
			icmpDestUnreachOutputChan != nil && scanner.icmpv6DestUnreachParser.Parser != nil {
			switch scanner.parser.ICMPv6.TypeCode.Type() {
			case layers.ICMPv6TypeDestinationUnreachable:
				icmpDestUnreachOutputChan <- scanner.GetICMPv6DestUnreachableOutput(recvTime)
			}
		}
		return false
	}
	srcPort := scanner.parser.UDP.SrcPort
	dstPort := scanner.parser.UDP.DstPort
	// validate source port
	if srcPort != layers.UDPPort(53) {
		return false
	}
	// validate destination port
	if !CheckDestPort(uint16(dstPort), int(numOfSrcPorts), validation) {
		return false
	}
	// validate udp dnsID
	dnsID := binary.BigEndian.Uint16(validation[:2])
	return scanner.parser.DNS.ID == dnsID
}

// GetICMPv6DestUnreachableOutput generates a detailed log of the received ICMPv6
// Destination Unreachable packet. It also parses the inner layers which should
// contain the original packet.
func (scanner *UDPDNSScanModule) GetICMPv6DestUnreachableOutput(recvTime time.Time) string {
	mainParser := scanner.parser
	parser := scanner.icmpv6DestUnreachParser
	// Payload[4:] to ignore the unused part of the Destination Unreachable packet
	// Reference: https://www.rfc-editor.org/rfc/rfc4443.html#page-8
	err := parser.Parser.DecodeLayers(mainParser.ICMPv6.BaseLayer.Payload[4:], parser.Decoded)
	if err != nil {
		// log.Warnf("error decoding packet for ICMPv6 Destination Unreachables: %s", err)
		// log.Warnf("Decoded: %+v", scanner.icmpv6DestUnreachParser.Decoded)
		// log.Warnf("IP: %+v", scanner.icmpv6DestUnreachParser.IP6)
		// log.Warnf("S-IP: %s", scanner.icmpv6DestUnreachParser.IP6.SrcIP)
		// log.Warnf("D-IP: %s", scanner.icmpv6DestUnreachParser.IP6.DstIP)
		targetIP := "could not decode"
		innerIPLayerDecoded := false
		// check if the parser was successfull to parse the original IP layer for target address
		for _, typ := range *parser.Decoded {
			switch typ {
			case layers.LayerTypeIPv6:
				targetIP = parser.IP6.DstIP.String()
				innerIPLayerDecoded = true
			}
			if innerIPLayerDecoded {
				break
			}
		}
		return fmt.Sprintf("{\"error\": \"%s\", \"saddr\": \"%s\", \"daddr\": \"%s\", \"taddr\": \"%s\"}",
			err, mainParser.IP6.SrcIP.String(), mainParser.IP6.DstIP.String(), targetIP)
	}
	// parse the IP addresses and expand them if necessary
	var dstIP, srcIP, targetIP string
	if conf.Expanded {
		srcIP = Explode(mainParser.IP6.SrcIP)
		dstIP = Explode(mainParser.IP6.DstIP)
		targetIP = Explode(parser.IP6.DstIP)
	} else {
		srcIP = mainParser.IP6.SrcIP.String()
		dstIP = mainParser.IP6.DstIP.String()
		targetIP = parser.IP6.DstIP.String()
	}
	o := &DNSInICMPv6DestUnreachOutput{
		Timestamp:        recvTime.UnixNano(),
		SrcIP:            srcIP,
		DstIP:            dstIP,
		TargetIP:         targetIP,
		Type:             mainParser.ICMPv6.TypeCode.Type(),
		Code:             mainParser.ICMPv6.TypeCode.Code(),
		IPFlowLabel:      mainParser.IP6.FlowLabel,
		SentFlowLabel:    parser.IP6.FlowLabel,
		IPHopLimit:       mainParser.IP6.HopLimit,
		InIPHopLimit:     parser.IP6.HopLimit,
		IPTrafficClass:   mainParser.IP6.TrafficClass,
		SentSrcPort:      uint16(parser.UDP.SrcPort),
		SentDstPort:      uint16(parser.UDP.DstPort),
		SentDomain:       scanner.Flags.Domain,
		SentDNSID:        parser.DNS.ID,
		SentDNSQueryType: scanner.Flags.UDPQueryType,
	}
	for i := range parser.DNS.Questions {
		if len(parser.DNS.Questions[i].Name) != 0 {
			o.SentQuestions = append(o.SentQuestions, string(parser.DNS.Questions[i].Name))
		}
	}

	// marshall the output into a string object
	b, err := json.Marshal(o)
	if err == nil {
		return string(b)
	} else {
		return fmt.Sprintf("{\"saddr\": %s, \"daddr\": %s, \"error\": \"error while json marshalling\"}", srcIP, dstIP)
	}
}

// checkResponseQuestion is being used as a helper function for ProcessPacket
// to validate if the domain names within the response question field matches
// the one determined for scan.
func (scanner *UDPDNSScanModule) checkResponseQuestion(question layers.DNSQuestion) bool {
	return (string(question.Name) == scanner.Flags.Domain)
}

// ProcessPacket processes the network packet according to module
// specifications and makes sures that it is a positive result or not.
// Validation bits makes sure that the scanner receives a valid and correct
// response from a correct target.
func (scanner *UDPDNSScanModule) ProcessPacket(data []byte, validation []byte) bool {
	if scanner.parser.IP6.NextHeader == layers.IPProtocolUDP {
		// Check if the question is what we have send.
		for _, question := range scanner.parser.DNS.Questions {
			if !scanner.checkResponseQuestion(question) {
				return false
			}
		}
		// Check if the question is what we have send.
		for _, question := range scanner.parser.DNS.Questions {
			if !scanner.checkResponseQuestion(question) {
				return false
			}
		}
		return true
	} else if scanner.parser.IP6.NextHeader != layers.IPProtocolICMPv6 {
		return false
	}
	return false
}

// GetDetailedOutputOfPacket generates a string representation of the received packet
// (or currently parsed within this scanner object). This is expected to be in JSON format,
// but users can code their own reporting scheme by using this function.
func (scanner *UDPDNSScanModule) GetDetailedOutputOfPacket(success bool, recvTime time.Time, validation []byte) string {
	// parse the IP addresses and expand them if necessary
	var dstIP, srcIP string
	if conf.Expanded {
		srcIP = Explode(scanner.parser.IP6.SrcIP)
		dstIP = Explode(scanner.parser.IP6.DstIP)
	} else {
		srcIP = scanner.parser.IP6.SrcIP.String()
		dstIP = scanner.parser.IP6.DstIP.String()
	}
	o := &dnsOutput{Resolver: srcIP, IP: dstIP, DstPort: uint16(scanner.parser.UDP.DstPort), SrcPort: 53,
		Domain: scanner.Flags.Domain, TTL: scanner.parser.IP6.HopLimit,
		DNSQueryType: scanner.Flags.UDPQueryType,
		Answers:      make([]dnsAnswer, 0), Questions: make([]string, 0),
		NS: make([]string, 0), DNSID: scanner.parser.DNS.ID,
		Status: scanner.parser.DNS.ResponseCode.String(), Timestamp: recvTime.UnixNano(),
		ProbeNum:        GetProbeNumberFromSourcePort(int(numOfSrcPorts), uint16(scanner.parser.UDP.DstPort), validation),
		Success:         success,
		IPFlowLabel:     scanner.parser.IP6.FlowLabel,
		IPFlowLabelSent: binary.BigEndian.Uint32(validation[8:12]) & 0x000FFFFF,
		IPHopLimit:      scanner.parser.IP6.HopLimit,
		IPTrafficClass:  scanner.parser.IP6.TrafficClass,
	}

	// parse the questions
	for i := range scanner.parser.DNS.Questions {
		if len(scanner.parser.DNS.Questions[i].Name) != 0 {
			o.Questions = append(o.Questions, string(scanner.parser.DNS.Questions[i].Name))
		}
	}

	// parse the answers
	for i := range scanner.parser.DNS.Answers {
		ans := scanner.parser.DNS.Answers[i]
		// For A and AAAA records
		if ans.IP != nil && (ans.Type == layers.DNSTypeA || ans.Type == layers.DNSTypeAAAA) {
			// o.QueryTypes = append(o.QueryTypes, ans.Type.String())
			o.Answers = append(o.Answers, dnsAnswer{Type: ans.Type.String(), Data: ans.IP.String()})
		}

		// For TXT records
		if len(ans.TXTs) > 0 && ans.Type == layers.DNSTypeTXT {
			if len(ans.TXTs) > 1 {
				if string(ans.TXTs[0]) == "ns" {
					// For TXTs if it gives ns, log it to the NS part
					// o.QueryTypes = append(o.QueryTypes, ans.Type.String())
					o.NS = append(o.NS, string(ans.TXTs[1]))
				}
			} else {
				o.Answers = append(o.Answers, dnsAnswer{Type: ans.Type.String(), Data: string(ans.TXTs[0])})
			}
		}
	}

	// marshall the output into a string object
	b, err := json.Marshal(o)
	if err == nil {
		return string(b)
	} else {
		return fmt.Sprintf("{\"saddr\": %s, \"daddr\": %s, \"error\": \"error while json marshalling\"}", srcIP, dstIP)
	}
}

// GetPcapFilter returns the pcap filter defined for the module.
func (scanner *UDPDNSScanModule) GetPcapFilter() string {
	return scanner.PcapFilter
}

// GetRecvShardFilter appends the shard related information to pcap
// filter and returns it.
func (scanner *UDPDNSScanModule) GetRecvShardFilter(shardID int) string {
	// Using last byte of the destination port as shard filter
	return " && ((ip6[43] & " + strconv.Itoa(conf.Receivers-1) + ") == " + strconv.Itoa(shardID) + ")"
}

// ParsePacket parses the received network packet into the header objects
// stored in the scanner instance for other functions to use.
func (scanner *UDPDNSScanModule) ParsePacket(data []byte) error {
	err := scanner.parser.Parser.DecodeLayers(data, scanner.parser.Decoded)
	if err != nil {
		log.Warnf("error decoding packet: %s", err)
		return err
	}
	return nil
}
