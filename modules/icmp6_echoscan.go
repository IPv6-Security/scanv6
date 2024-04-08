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

	b64 "encoding/base64"
)

// Module specific flags.
type ICMP6EchoScanFlags struct {
}

// Module Scanner Instance. It holds the pcap filter
// objects to parse each network packet layer into
// parser object, and the module specific flags.
type ICMP6EchoScanModule struct {
	PcapFilter              string
	ethHdr                  *layers.Ethernet
	ip6Hdr                  *layers.IPv6
	icmp6Hdr                *layers.ICMPv6
	icmp6EchoHdr            *layers.ICMPv6Echo
	packetPayload           gopacket.Payload
	parser                  *ModulePacketParser
	icmpv6DestUnreachParser *ICMPv6DestUnreachParser
	Flags                   *ICMP6EchoScanFlags
}

// Output object for detailed output
type icmp6EchoOutput struct {
	SrcIP           string `json:"saddr"`
	DstIP           string `json:"daddr"`
	IPFlowLabel     uint32 `json:"ip_flow_label"`
	IPFlowLabelSent uint32 `json:"ip_flow_label_sent"`
	IPHopLimit      uint8  `json:"ip_hop_limit"`
	IPTrafficClass  uint8  `json:"ip_traffic_class"`
	ProbeNum        int    `json:"probe_num"`
	Success         bool   `json:"success"`
	Type            uint8  `json:"type"`
	Code            uint8  `json:"code"`
	ID              uint16 `json:"id"`
	SEQ             uint16 `json:"seq"`
	Payload         string `json:"payload"`
	Timestamp       int64  `json:"timestamp_ns"`
}

// Output object for ICMPv6 Destination Unreachable output
type ICMPv6InICMPv6DestUnreachOutput struct {
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
	SentType       uint8  `json:"sent_type"`
	SentCode       uint8  `json:"sent_code"`
	SentID         uint16 `json:"sent_id"`
	SentSEQ        uint16 `json:"sent_seq"`
	SentPayload    string `json:"sent_payload"`
	Timestamp      int64  `json:"timestamp_ns"`
}

// init function registers the module into the scanner program.
func init() {
	RegisterICMP6EchoModule()
}

// RegisterICMP6EchoModule adds this module to the list of
// available modules with the summary information, a function
// to create a fresh scanner module object and module
// specific flags object for this module.
func RegisterICMP6EchoModule() {
	AVAILABLE_MODULES = append(AVAILABLE_MODULES, ModuleEntry{
		ModuleName:   "icmp6_echoscan",
		ShortDesc:    "IPv6 ICMP Echo Scan",
		LongDesc:     "Probe module that sends ICMP6 Echo Requests to hosts",
		CreateModule: func() (Module, int) { return new(ICMP6EchoScanModule), 6 },
		Flags:        new(ICMP6EchoScanFlags),
	})
}

// ValidateFlags validates module specific flags if there is any.
// It should raise a FATAL error if the validation fails.
func (sf *ICMP6EchoScanFlags) ValidateFlags() {
}

// ValidateFlags is a wrapper to call validation function for
// module specific flags
func (scanner *ICMP6EchoScanModule) ValidateFlags() {
	scanner.Flags.ValidateFlags()
}

// SetFlags deep copies the given module specific object to
// module's flag object
func (scanner *ICMP6EchoScanModule) SetFlags(val ModuleFlags) {
	scanner.Flags = GetDeepCopyModuleFlags(val).(*ICMP6EchoScanFlags)
}

// Init initializes the scanner module. This is generally
// used for setting the pcap filter with the correct
// IP address (source IP of the scanner).
func (scanner *ICMP6EchoScanModule) Init() {
	scanner.PcapFilter = fmt.Sprintf("(icmp6 && (ip6[40] == 129 || ip6[40] == 1) && ip6 dst host %s)", conf.SourceAddress)
	// The following actually receives all ICMPv6 Errors, not only the Dest. Unreachables.
	// 1. Destination Unreachable
	// 2. Packet Too Big
	// 3. Time Exceeded
	// 4. Parameter Problem
	// scanner.PcapFilter = fmt.Sprintf("(icmp6 && (ip6[40] == 129 || ip6[40] == 1 || ip6[40] == 2 || ip6[40] == 3 || ip6[40] == 4) && ip6 dst host %s)", conf.SourceAddress)
}

// ThreadInit does the thread specific initilizations (related to
// pointers and parsers).
func (scanner *ICMP6EchoScanModule) ThreadInit() {
	scanner.ethHdr = MakeEthHeader(layers.EthernetTypeIPv6)
	scanner.ip6Hdr = MakeIP6Header(layers.IPProtocolICMPv6)
	scanner.icmp6Hdr = MakeICMP6Header()
	scanner.icmp6EchoHdr = MakeICMP6EchoHeader()
	scanner.packetPayload = make([]byte, 2)
	scanner.parser = MakeNewModulePacketParser()
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, scanner.parser.ETH,
		scanner.parser.IP6, scanner.parser.ICMPv6, &scanner.parser.Payload)
	parser.IgnoreUnsupported = true // avoid `No decoder for layer type ICMPv6RouterAdvertisement` error
	scanner.parser.Parser = parser
	parser = nil

	scanner.icmpv6DestUnreachParser = MakeNewICMPv6DestUnreachableParser()
	if conf.ICMPDestUnreachableOutput != "" {
		scanner.icmpv6DestUnreachParser.Parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6,
			scanner.icmpv6DestUnreachParser.IP6, scanner.icmpv6DestUnreachParser.ICMPv6,
			&scanner.icmpv6DestUnreachParser.Payload)
		scanner.icmpv6DestUnreachParser.Parser.IgnoreUnsupported = true
	}
}

// MakePacket compiles a network packet based on the module specifications.
// It needs to embed validation bits to some part of the packet
// to enable scanner verify whether the responses belong to the
// scan activity or not.
func (scanner *ICMP6EchoScanModule) MakePacket(probeNum int, dstIP net.IP, validation []byte) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// identifier would be validation[16:18]
	id := binary.BigEndian.Uint16(validation[16:18])
	scanner.icmp6EchoHdr.Identifier = id

	scanner.icmp6EchoHdr.SeqNumber = uint16(probeNum)

	// embed the probe number based on validation bits into payload
	valFirst2 := GetSourcePort(int(numOfSrcPorts), probeNum, validation)
	binary.BigEndian.PutUint16(scanner.packetPayload[:2], valFirst2)

	// set the target IP
	scanner.ip6Hdr.DstIP = dstIP

	// set a random flowLabel
	flowLabel := binary.BigEndian.Uint32(validation[8:12])
	scanner.ip6Hdr.FlowLabel = flowLabel & 0x000FFFFF

	// calculate the checksums and create the packet
	scanner.icmp6Hdr.SetNetworkLayerForChecksum(scanner.ip6Hdr)
	if err := gopacket.SerializeLayers(buf, opts, scanner.ethHdr, scanner.ip6Hdr,
		scanner.icmp6Hdr, scanner.icmp6EchoHdr, scanner.packetPayload); err != nil {
		log.Errorf("error while serializing the packet: %s", err)
	}
	return buf.Bytes()
}

// PrintPacket creates a string representation of the packet
// for dry-run mode.
func (scanner *ICMP6EchoScanModule) PrintPacket() {
	// TODO: for dry-run
}

// Name returns the name of the module
func (scanner *ICMP6EchoScanModule) Name() string {
	return "icmp6_echoscan"
}

// ValidatePacket validates the received network packet according to
// module specifications. It may or may not use the validation
// bits as well as destination IP (target IP).
func (scanner *ICMP6EchoScanModule) ValidatePacket(data []byte, srcIP net.IP, dstIP net.IP,
	validation []byte, recvTime time.Time, icmpDestUnreachOutputChan chan string) bool {
	if scanner.parser.IP6.NextHeader != layers.IPProtocolICMPv6 {
		return false
	}

	// validate the packet type
	switch scanner.parser.ICMPv6.TypeCode.Type() {
	case layers.ICMPv6TypeEchoReply:
		return true
	case layers.ICMPv6TypeDestinationUnreachable:
		if icmpDestUnreachOutputChan != nil && scanner.icmpv6DestUnreachParser.Parser != nil {
			icmpDestUnreachOutputChan <- scanner.GetICMPv6DestUnreachableOutput(recvTime)
		}
		switch scanner.parser.ICMPv6.TypeCode.Code() {
		case layers.ICMPv6CodeNoRouteToDst, layers.ICMPv6CodeAdminProhibited,
			layers.ICMPv6CodeBeyondScopeOfSrc, layers.ICMPv6CodeAddressUnreachable,
			layers.ICMPv6CodePortUnreachable, layers.ICMPv6CodeSrcAddressFailedPolicy,
			layers.ICMPv6CodeRejectRouteToDst:
			return false
		default:
			return false
		}
	case layers.ICMPv6TypePacketTooBig, layers.ICMPv6TypeParameterProblem,
		layers.ICMPv6TypeTimeExceeded:
		return false
	default:
		return false
	}
}

// GetICMPv6DestUnreachableOutput generates a detailed log of the received ICMPv6
// Destination Unreachable packet. It also parses the inner layers which should
// contain the original packet.
func (scanner *ICMP6EchoScanModule) GetICMPv6DestUnreachableOutput(recvTime time.Time) string {
	mainParser := scanner.parser
	parser := scanner.icmpv6DestUnreachParser
	// Payload[4:] to ignore the unused part of the Destination Unreachable packet
	// Reference: https://www.rfc-editor.org/rfc/rfc4443.html#page-8
	err := parser.Parser.DecodeLayers(scanner.parser.ICMPv6.BaseLayer.Payload[4:], parser.Decoded)
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

	identifier := uint16(0xFFFF)
	seqNumber := uint16(0xFFFF)
	payload := ""
	if len(parser.ICMPv6.BaseLayer.Payload) >= 2 {
		identifier = binary.BigEndian.Uint16(parser.ICMPv6.BaseLayer.Payload[0:2])
	}
	if len(parser.ICMPv6.BaseLayer.Payload) >= 4 {
		seqNumber = binary.BigEndian.Uint16(parser.ICMPv6.BaseLayer.Payload[2:4])
	}
	if len(parser.ICMPv6.BaseLayer.Payload) >= 6 {
		payload = b64.StdEncoding.EncodeToString(parser.ICMPv6.BaseLayer.Payload[4:6])
	}
	o := &ICMPv6InICMPv6DestUnreachOutput{
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
		SentID:         identifier,
		SentSEQ:        seqNumber,
		SentType:       parser.ICMPv6.TypeCode.Type(),
		SentCode:       parser.ICMPv6.TypeCode.Code(),
		SentPayload:    payload,
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
func (scanner *ICMP6EchoScanModule) ProcessPacket(data []byte, validation []byte) bool {
	// parse the ICMP6 header fields for processing
	if len(scanner.parser.ICMPv6.BaseLayer.Payload) < 6 {
		return false
	}
	identifier := binary.BigEndian.Uint16(scanner.parser.ICMPv6.BaseLayer.Payload[0:2])
	seqNumber := binary.BigEndian.Uint16(scanner.parser.ICMPv6.BaseLayer.Payload[2:4])
	valIdentifier := binary.BigEndian.Uint16(validation[16:18])

	payload := scanner.parser.ICMPv6.BaseLayer.Payload[4:]
	if len(payload) < 2 {
		return false
	}
	probeNum := GetProbeNumberFromSourcePort(int(numOfSrcPorts), binary.BigEndian.Uint16(payload[:2]), validation)

	// check if the payload is sent correctly or not
	if probeNum == -1 {
		return false
	}

	return identifier == valIdentifier && seqNumber == uint16(probeNum)
}

// GetDetailedOutputOfPacket generates a string representation of the received packet
// (or currently parsed within this scanner object). This is expected to be in JSON format,
// but users can code their own reporting scheme by using this function.
func (scanner *ICMP6EchoScanModule) GetDetailedOutputOfPacket(success bool, recvTime time.Time, validation []byte) string {
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
	identifier := binary.BigEndian.Uint16(scanner.parser.ICMPv6.BaseLayer.Payload[0:2])
	seqNumber := binary.BigEndian.Uint16(scanner.parser.ICMPv6.BaseLayer.Payload[2:4])
	payload := b64.StdEncoding.EncodeToString(scanner.parser.ICMPv6.BaseLayer.Payload[4:6])
	probeNum := GetProbeNumberFromSourcePort(int(numOfSrcPorts), binary.BigEndian.Uint16(scanner.parser.ICMPv6.BaseLayer.Payload[4:6]), validation)
	o := &icmp6EchoOutput{
		Timestamp: recvTime.UnixNano(), SrcIP: srcIP, DstIP: dstIP,
		ID: identifier, SEQ: seqNumber,
		Type:            scanner.parser.ICMPv6.TypeCode.Type(),
		Code:            scanner.parser.ICMPv6.TypeCode.Code(),
		Payload:         payload,
		ProbeNum:        probeNum,
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
func (scanner *ICMP6EchoScanModule) GetPcapFilter() string {
	return scanner.PcapFilter
}

// GetRecvShardFilter appends the shard related information to pcap
// filter and returns it.
func (scanner *ICMP6EchoScanModule) GetRecvShardFilter(shardID int) string {
	// Using last byte of the Identifier as shard filter
	return " && ((ip6[45] & " + strconv.Itoa(conf.Receivers-1) + ") == " + strconv.Itoa(shardID) + ")"
}

// ParsePacket parses the received network packet into the header objects
// stored in the scanner instance for other functions to use.
func (scanner *ICMP6EchoScanModule) ParsePacket(data []byte) error {
	err := scanner.parser.Parser.DecodeLayers(data, scanner.parser.Decoded)
	if err != nil {
		log.Warnf("error decoding packet: %s", err)
		return err
	}
	return nil
}
