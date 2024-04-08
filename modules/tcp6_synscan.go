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
type TCP6SynScanFlags struct {
}

// Module Scanner Instance. It holds the pcap filter
// objects to parse each network packet layer into
// parser object, and the module specific flags.
type TCP6SynScanModule struct {
	PcapFilter              string
	ethHdr                  *layers.Ethernet
	ip6Hdr                  *layers.IPv6
	tcpHdr                  *layers.TCP
	parser                  *ModulePacketParser
	icmpv6DestUnreachParser *ICMPv6DestUnreachParser
	Flags                   *TCP6SynScanFlags
}

// Output object for detailed output.
type tcp6SynOutput struct {
	SrcIP           string `json:"saddr"`
	DstIP           string `json:"daddr"`
	SrcPort         uint16 `json:"sport"`
	DstPort         uint16 `json:"dport"`
	IPFlowLabel     uint32 `json:"ip_flow_label"`
	IPFlowLabelSent uint32 `json:"ip_flow_label_sent"`
	IPHopLimit      uint8  `json:"ip_hop_limit"`
	IPTrafficClass  uint8  `json:"ip_traffic_class"`
	ProbeNum        int    `json:"probe_num"`
	Success         bool   `json:"success"`
	Synack          bool   `json:"synack"`
	SeqSent         uint32 `json:"seq_sent"`
	SeqRecv         uint32 `json:"seq_recv"`
	Ack             uint32 `json:"ack"`
	Window          uint16 `json:"window"`
	Checksum        uint16 `json:"checksum"`
	Urgent          uint16 `json:"urgent"`
	Timestamp       int64  `json:"timestamp_ns"`
}

// Output object for ICMPv6 Destination Unreachable output
type TCPInICMPv6DestUnreachOutput struct {
	SrcIP          string `json:"saddr"`
	DstIP          string `json:"daddr"`
	TargetIP       string `json:"taddr"`
	IPFlowLabel    uint32 `json:"ip_flow_label"`
	SentFlowLabel  uint32 `json:"sent_ip_flow_label"`
	IPHopLimit     uint8  `json:"ip_hop_limit"`
	InIPHopLimit   uint8  `json:"inner_ip_hop_limit"`
	IPTrafficClass uint8  `json:"ip_traffic_class"`
	Type           uint8  `json:"type"`
	Code           uint8  `json:"code"`
	SentSeq        uint32 `json:"sent_seq"`
	SentSrcPort    uint16 `json:"sent_sport"`
	SentDstPort    uint16 `json:"sent_dport"`
	SentAck        uint32 `json:"sent_ack"`
	SentWindow     uint16 `json:"sent_window"`
	SentChecksum   uint16 `json:"sent_checksum"`
	SentUrgent     uint16 `json:"sent_urgent"`
	SentSyn        bool   `json:"sent_syn"`
	Timestamp      int64  `json:"timestamp_ns"`
}

// init function registers the module into the scanner program.
func init() {
	RegisterTCP6SynModule()
}

// RegisterTCP6SynModule adds this module to the list of
// available modules with the summary information, a function
// to create a fresh scanner module object and module
// specific flags object for this module.
func RegisterTCP6SynModule() {
	AVAILABLE_MODULES = append(AVAILABLE_MODULES, ModuleEntry{
		ModuleName: "tcp6_synscan",
		ShortDesc:  "IPv6 TCP SYN Scan",
		LongDesc: "Probe module that sends an IPv6 TCP SYN packet to a specific " +
			"port. Possible classifications are: synack and rst. A " +
			"SYN-ACK packet is considered a success and a reset packet " +
			"is considered a failed response.",
		CreateModule: func() (Module, int) { return new(TCP6SynScanModule), 6 },
		Flags:        new(TCP6SynScanFlags),
	})
}

// ValidateFlags validates module specific flags if there is any.
// It should raise a FATAL error if the validation fails.
func (sf *TCP6SynScanFlags) ValidateFlags() {
	if conf.TargetPort < 0 {
		log.Fatal("this module requires the target port to be set")
	}
}

// ValidateFlags is a wrapper to call validation function for
// module specific flags
func (scanner *TCP6SynScanModule) ValidateFlags() {
	scanner.Flags.ValidateFlags()
}

// SetFlags deep copies the given module specific object to
// module's flag object
func (scanner *TCP6SynScanModule) SetFlags(val ModuleFlags) {
	scanner.Flags = GetDeepCopyModuleFlags(val).(*TCP6SynScanFlags)
}

// Init initializes the scanner module. This is generally
// used for setting the pcap filter with the correct
// IP address (source IP of the scanner).
func (scanner *TCP6SynScanModule) Init() {
	scanner.PcapFilter = fmt.Sprintf("(((ip6 proto 6 && (ip6[53] & 4 != 0 || ip6[53] == 18)) || (icmp6 && (ip6[40] == 1))) && ip6 dst host %s)", conf.SourceAddress)
}

// ThreadInit does the thread specific initilizations (related to
// pointers and parsers).
func (scanner *TCP6SynScanModule) ThreadInit() {
	scanner.ethHdr = MakeEthHeader(layers.EthernetTypeIPv6)
	scanner.ip6Hdr = MakeIP6Header(layers.IPProtocolTCP)
	scanner.tcpHdr = MakeTCPSynHeader()
	scanner.parser = MakeNewModulePacketParser()
	scanner.parser.Parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, scanner.parser.ETH, scanner.parser.IP6, scanner.parser.ICMPv6, scanner.parser.TCP)
	scanner.parser.Parser.IgnoreUnsupported = true // avoid `No decoder for layer type ICMPv6RouterAdvertisement` error

	scanner.icmpv6DestUnreachParser = MakeNewICMPv6DestUnreachableParser()
	if conf.ICMPDestUnreachableOutput != "" {
		scanner.icmpv6DestUnreachParser.Parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6,
			scanner.icmpv6DestUnreachParser.IP6, scanner.icmpv6DestUnreachParser.TCP,
			&scanner.icmpv6DestUnreachParser.Payload)
		scanner.icmpv6DestUnreachParser.Parser.IgnoreUnsupported = true
	}
}

// MakePacket compiles a network packet based on the module specifications.
// It needs to embed validation bits to some part of the packet
// to enable scanner verify whether the responses belong to the
// scan activity or not.
func (scanner *TCP6SynScanModule) MakePacket(probeNum int, dstIP net.IP, validation []byte) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// sequence would be validation[:4]
	seq := binary.BigEndian.Uint32(validation[:4])

	// set the source port, sequence and the checksum
	scanner.tcpHdr.Seq = seq
	scanner.tcpHdr.Checksum = 0
	scanner.tcpHdr.SrcPort = layers.TCPPort(GetSourcePort(int(numOfSrcPorts), probeNum, validation))

	// set the target IP
	scanner.ip6Hdr.DstIP = dstIP

	// set a random flowLabel
	flowLabel := binary.BigEndian.Uint32(validation[8:12])
	scanner.ip6Hdr.FlowLabel = flowLabel & 0x000FFFFF

	// calculate the checksums and create the packet
	scanner.tcpHdr.SetNetworkLayerForChecksum(scanner.ip6Hdr)
	if err := gopacket.SerializeLayers(buf, opts, scanner.ethHdr, scanner.ip6Hdr, scanner.tcpHdr); err != nil {
		log.Error(err)
	}
	return buf.Bytes()
}

// PrintPacket creates a string representation of the packet
// for dry-run mode.
func (scanner *TCP6SynScanModule) PrintPacket() {
	// TODO: for dry-run
}

// Name returns the name of the module
func (scanner *TCP6SynScanModule) Name() string {
	return "tcp6_synscan"
}

// ValidatePacket validates the received network packet according to
// module specifications. It may or may not use the validation
// bits as well as destination IP (target IP).
func (scanner *TCP6SynScanModule) ValidatePacket(data []byte, srcIP net.IP, dstIP net.IP,
	validation []byte, recvTime time.Time, icmpDestUnreachOutputChan chan string) bool {
	if scanner.parser.IP6.NextHeader != layers.IPProtocolTCP {
		if scanner.parser.IP6.NextHeader == layers.IPProtocolICMPv6 &&
			icmpDestUnreachOutputChan != nil && scanner.icmpv6DestUnreachParser.Parser != nil {
			switch scanner.parser.ICMPv6.TypeCode.Type() {
			case layers.ICMPv6TypeDestinationUnreachable:
				icmpDestUnreachOutputChan <- scanner.GetICMPv6DestUnreachableOutput(recvTime)
			}
		}
		return false
	}

	// validate the packet type
	if !(scanner.parser.TCP.SYN && scanner.parser.TCP.ACK) || (scanner.parser.TCP.RST) {
		return false
	}

	srcPort := scanner.parser.TCP.SrcPort
	dstPort := scanner.parser.TCP.DstPort
	// validate source port
	if srcPort != layers.TCPPort(conf.TargetPort) {
		return false
	}

	// validate destination port
	if !CheckDestPort(uint16(dstPort), int(numOfSrcPorts), validation) {
		return false
	}

	return true
}

// GetICMPv6DestUnreachableOutput generates a detailed log of the received ICMPv6
// Destination Unreachable packet. It also parses the inner layers which should
// contain the original packet.
func (scanner *TCP6SynScanModule) GetICMPv6DestUnreachableOutput(recvTime time.Time) string {
	mainParser := scanner.parser
	parser := scanner.icmpv6DestUnreachParser
	// Payload[4:] to ignore the unused part of the Destination Unreachable packet
	// Reference: https://www.rfc-editor.org/rfc/rfc4443.html#page-8
	err := parser.Parser.DecodeLayers(mainParser.ICMPv6.BaseLayer.Payload[4:], parser.Decoded)
	if err != nil {
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

	o := &TCPInICMPv6DestUnreachOutput{
		Timestamp:      recvTime.UnixNano(),
		SrcIP:          srcIP,
		DstIP:          dstIP,
		TargetIP:       targetIP,
		Type:           mainParser.ICMPv6.TypeCode.Type(),
		Code:           mainParser.ICMPv6.TypeCode.Code(),
		IPFlowLabel:    mainParser.IP6.FlowLabel,
		SentFlowLabel:  parser.IP6.FlowLabel,
		IPHopLimit:     mainParser.IP6.HopLimit,
		InIPHopLimit:   parser.IP6.HopLimit,
		IPTrafficClass: mainParser.IP6.TrafficClass,
		SentSrcPort:    uint16(parser.TCP.SrcPort),
		SentDstPort:    uint16(parser.TCP.DstPort),
		SentSeq:        parser.TCP.Seq,
		SentAck:        parser.TCP.Ack,
		SentWindow:     parser.TCP.Window,
		SentChecksum:   parser.TCP.Checksum,
		SentUrgent:     parser.TCP.Urgent,
		SentSyn:        parser.TCP.SYN,
	}

	// marshall the output into a string object
	b, err := json.Marshal(o)
	if err == nil {
		return string(b)
	} else {
		return fmt.Sprintf("{\"saddr\": %s, \"daddr\": %s, \"error\": \"error while json marshalling\"}", srcIP, dstIP)
	}
}

// ProcessPacket processes the network packet according to module
// specifications and makes sures that it is a positive result or not.
// Validation bits makes sure that the scanner receives a valid and correct
// response from a correct target.
func (scanner *TCP6SynScanModule) ProcessPacket(data []byte, validation []byte) bool {
	// At this point, we know that the packet has correct IPs and ports,
	// and the packet is a SYN-ACK Packet, not a RST packet.
	// Thus, we need to validate the TCP acknowledgement number
	seq := binary.BigEndian.Uint32(validation[:4])
	return scanner.parser.TCP.Ack == (seq + 1)
}

// GetDetailedOutputOfPacket generates a string representation of the received packet
// (or currently parsed within this scanner object). This is expected to be in JSON format,
// but users can code their own reporting scheme by using this function.
func (scanner *TCP6SynScanModule) GetDetailedOutputOfPacket(success bool, recvTime time.Time, validation []byte) string {
	// parse the IP addresses and expand them if necessary
	var dstIP, srcIP string
	if conf.Expanded {
		srcIP = Explode(scanner.parser.IP6.SrcIP)
		dstIP = Explode(scanner.parser.IP6.DstIP)
	} else {
		srcIP = scanner.parser.IP6.SrcIP.String()
		dstIP = scanner.parser.IP6.DstIP.String()
	}

	// parse the header fields and the payload
	o := &tcp6SynOutput{SrcIP: srcIP, DstIP: dstIP,
		SrcPort: uint16(scanner.parser.TCP.SrcPort), DstPort: uint16(scanner.parser.TCP.DstPort),
		SeqSent: binary.BigEndian.Uint32(validation[:4]),
		SeqRecv: scanner.parser.TCP.Seq, Ack: scanner.parser.TCP.Ack,
		Window: scanner.parser.TCP.Window, Checksum: scanner.parser.TCP.Checksum, Urgent: scanner.parser.TCP.Urgent,
		Synack:          scanner.parser.TCP.SYN && scanner.parser.TCP.ACK,
		ProbeNum:        GetProbeNumberFromSourcePort(int(numOfSrcPorts), uint16(scanner.parser.TCP.DstPort), validation),
		Timestamp:       recvTime.UnixNano(),
		Success:         success,
		IPFlowLabel:     scanner.parser.IP6.FlowLabel,
		IPFlowLabelSent: binary.BigEndian.Uint32(validation[8:12]) & 0x000FFFFF,
		IPHopLimit:      scanner.parser.IP6.HopLimit,
		IPTrafficClass:  scanner.parser.IP6.TrafficClass,
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
func (scanner *TCP6SynScanModule) GetPcapFilter() string {
	return scanner.PcapFilter
}

// GetRecvShardFilter appends the shard related information to pcap
// filter and returns it.
func (scanner *TCP6SynScanModule) GetRecvShardFilter(shardID int) string {
	// Using last byte of the destination port as shard filter
	return " && ((ip6[43] & " + strconv.Itoa(conf.Receivers-1) + ") == " + strconv.Itoa(shardID) + ")"
}

// ParsePacket parses the received network packet into the header objects
// stored in the scanner instance for other functions to use.
func (scanner *TCP6SynScanModule) ParsePacket(data []byte) error {
	err := scanner.parser.Parser.DecodeLayers(data, scanner.parser.Decoded)
	if err != nil {
		log.Warnf("error decoding packet: %s", err)
		return err
	}
	return nil
}
