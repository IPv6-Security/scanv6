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
	"net"
	"time"

	"scanv6/config"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mitchellh/copystructure"
	log "github.com/sirupsen/logrus"
)

// Global config object for all of the modules
var conf *config.Config

// Number of available source addresses and ports
var numOfSrcAddrs uint32
var numOfSrcPorts uint16

// Available modules
var AVAILABLE_MODULES = []ModuleEntry{}

// ModuleEntry represents an avaliable module in the scanner
// with a summary information along with a pointer to a
// function to create an instance.
type ModuleEntry struct {
	ModuleName   string
	ShortDesc    string
	LongDesc     string
	CreateModule func() (Module, int)
	Flags        ModuleFlags
}

// ModulePacketParser is used for parsing any type of network packet.
// It is being used in every module.
type ModulePacketParser struct {
	ETH     *layers.Ethernet
	TCP     *layers.TCP
	UDP     *layers.UDP
	IP4     *layers.IPv4
	IP6     *layers.IPv6
	ICMPv6  *layers.ICMPv6
	DNS     *layers.DNS
	Payload gopacket.Payload

	Decoded *[]gopacket.LayerType
	Parser  *gopacket.DecodingLayerParser
}

// ICMPv6DestUnreachParser is used for parsing ICMPv6 Layer
// to get further information about the initial packet
// sent by the scanner. It is being used in every module
// if logging is activated.
type ICMPv6DestUnreachParser struct {
	IP6     *layers.IPv6
	TCP     *layers.TCP
	UDP     *layers.UDP
	ICMPv6  *layers.ICMPv6
	DNS     *layers.DNS
	Payload gopacket.Payload

	Decoded *[]gopacket.LayerType
	Parser  *gopacket.DecodingLayerParser
}

// An interface that implements module specific flags
type ModuleFlags interface {
	ValidateFlags()
}

// An interface that implements a scanner module
type Module interface {
	Init()
	ThreadInit()
	SetFlags(ModuleFlags)
	ValidateFlags()
	MakePacket(int, net.IP, []byte) []byte
	PrintPacket()
	Name() string
	ValidatePacket([]byte, net.IP, net.IP, []byte, time.Time, chan string) bool
	ProcessPacket([]byte, []byte) bool
	GetDetailedOutputOfPacket(bool, time.Time, []byte) string
	GetICMPv6DestUnreachableOutput(time.Time) string
	GetPcapFilter() string
	GetRecvShardFilter(int) string
	ParsePacket([]byte) error
}

// LoadConfigAndInit parses the command line arguments and
// sets the global config object accordingly. It also sets
// global variables available to every module.
func LoadConfigAndInit(args []string) {
	conf = new(config.Config)
	_, _ = config.ParseCommandLine(conf, args, GetModuleCommands())
	numOfSrcAddrs = 1
	_ = numOfSrcAddrs
	numOfSrcPorts = conf.SourcePortLast - conf.SourcePortFirst + 1
}

// SetConfigAndInit creates a deep copy of the given configuration
// instance and points the global config to this new object.
// It also resets global variables.
func SetConfigAndInit(val *config.Config) {
	if val != nil {
		conf = nil
		conf = config.GetDeepCopyConfig(val)
	}
	numOfSrcAddrs = 1
	numOfSrcPorts = conf.SourcePortLast - conf.SourcePortFirst + 1
}

// GetModuleFlags returns the module specific flags
// for the given module in moduleName parameter.
func GetModuleFlags(moduleName string) ModuleFlags {
	for i := 0; i < len(AVAILABLE_MODULES); i++ {
		if AVAILABLE_MODULES[i].ModuleName == moduleName {
			return AVAILABLE_MODULES[i].Flags
		}
	}
	log.Fatalf("couldn't find a module named %s for flags", moduleName)
	return nil
}

// GetModuleCommands returns all available modules with
// their information defined in the each module.
func GetModuleCommands() []config.ModuleCommand {
	mcmds := make([]config.ModuleCommand, 0)
	for i := 0; i < len(AVAILABLE_MODULES); i++ {
		mcmds = append(mcmds, config.ModuleCommand{
			Command:   AVAILABLE_MODULES[i].ModuleName,
			ShortDesc: AVAILABLE_MODULES[i].ShortDesc,
			LongDesc:  AVAILABLE_MODULES[i].LongDesc,
			Data:      AVAILABLE_MODULES[i].Flags,
		})
	}
	return mcmds
}

// GetDeepCopyModuleFlags creates a deep copy of the
// module specific flags and validates them.
func GetDeepCopyModuleFlags(val ModuleFlags) ModuleFlags {
	if val == nil {
		return nil
	}
	dup, err := copystructure.Copy(val)
	if err != nil {
		log.Fatal("cannot create a deep copy of given module flags")
	}
	dup.(ModuleFlags).ValidateFlags()
	return dup.(ModuleFlags)
}

// GetModuleByName returns a fresh module instances
// chosen with the name parameter.
func GetModuleByName(name string) (Module, int) {
	for i := 0; i < len(AVAILABLE_MODULES); i++ {
		if name == AVAILABLE_MODULES[i].ModuleName {
			return AVAILABLE_MODULES[i].CreateModule()
		}
	}
	log.Fatalf("couldn't find and get a module named %s", name)
	return nil, -1
}

// GetSourcePort returns a source port by using the validation bits.
func GetSourcePort(numPorts int, probeNum int, validation []byte) uint16 {
	valUint32 := binary.BigEndian.Uint32(validation[4:8])
	return conf.SourcePortFirst + uint16((valUint32+uint32(probeNum))%uint32(numPorts))
}

// GetProbeNumberFromSourcePort parses the probe number from the the source port.
func GetProbeNumberFromSourcePort(numPorts int, srcPort uint16, validation []byte) int {
	// get the source port
	valUint32 := binary.BigEndian.Uint32(validation[4:8])

	// check this source port against all possible source ports
	for probeNum := 0; probeNum < conf.Probes; probeNum++ {
		if srcPort == (conf.SourcePortFirst + uint16((valUint32+uint32(probeNum))%uint32(numPorts))) {
			return probeNum
		}
	}
	// this actually indicates that source port does not belong to any of our probes. It should be
	// investigated if present.
	return -1
}

// ChecktDestPort checks the destination port is valid and within
// available range.
func CheckDestPort(port uint16, numPorts int, validation []byte) bool {
	if port > conf.SourcePortLast || port < conf.SourcePortFirst {
		return false
	}
	valUint32 := binary.BigEndian.Uint32(validation[4:8])
	toValidate := port - conf.SourcePortFirst
	min := valUint32 % uint32(numPorts)
	max := (valUint32 + uint32(conf.Probes) - 1) % uint32(numPorts)
	return ((max-min)%uint32(numPorts) >= (uint32(toValidate)-min)%uint32(numPorts))
}

// MakeNewModulePacketParser returns a fresh packet parser for
// modules
func MakeNewModulePacketParser() *ModulePacketParser {
	return &ModulePacketParser{
		ETH:     &layers.Ethernet{},
		IP4:     &layers.IPv4{},
		IP6:     &layers.IPv6{},
		UDP:     &layers.UDP{},
		TCP:     &layers.TCP{},
		ICMPv6:  &layers.ICMPv6{},
		DNS:     &layers.DNS{},
		Payload: gopacket.Payload{},
		Decoded: new([]gopacket.LayerType),
		Parser:  nil,
	}
}

// MakeNewICMPv6DestUnreachableParser returns a fresh packet parser for
// ICMPv6 Destination Unreachables
func MakeNewICMPv6DestUnreachableParser() *ICMPv6DestUnreachParser {
	return &ICMPv6DestUnreachParser{
		IP6:     &layers.IPv6{},
		UDP:     &layers.UDP{},
		TCP:     &layers.TCP{},
		ICMPv6:  &layers.ICMPv6{},
		DNS:     &layers.DNS{},
		Payload: gopacket.Payload{},
		Decoded: new([]gopacket.LayerType),
		Parser:  nil,
	}
}
