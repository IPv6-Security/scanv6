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

// Some parts of this code is modified from:
// https://github.com/zmap/zgrab2/blob/178d984996c518848e8c1133b6ce52ffaa621579/config.go
package config

import (
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	"scanv6/utility"

	flags "github.com/jessevdk/go-flags"
	"github.com/mitchellh/copystructure"
	log "github.com/sirupsen/logrus"
)

// Scanner Global Configuration Object
type Config struct {
	BlocklistFileName         string         `short:"b" long:"blocklist-file" default:"/etc/zmap/blocklist6" description:"File of subnets to exclude, in CIDR notation."`
	OutputFileName            string         `short:"o" long:"output-file" default:"-" description:"Output filename, use - for stdout"`
	InputFileName             string         `short:"f" long:"input-file" default:"-" description:"Input filename, use - for stdin"`
	DetailedOutput            string         `short:"d" long:"detailed-output-file" default:"" description:"Detailed Scan Results filename"`
	ICMPDestUnreachableOutput string         `long:"icmp-dest-unreach-output-file" default:"" description:"ICMPv6 Destination Unreachables Output filename"`
	MetaFileName              string         `short:"m" long:"metadata-file" default:"-" description:"Metadata filename, use - for stderr"`
	LogFileName               string         `short:"l" long:"log-file" default:"-" description:"Log filename, use - for stderr"`
	ConfigFileName            func(s string) `long:"config-file" description:"Config filename, use - for stdin. You need to pass this to cmd along with the module name you want to run" no-ini:"true"`
	Rate                      int            `short:"r" long:"rate" default:"1000" description:"Number of packets to send/sec"`
	Senders                   int            `short:"s" long:"senders" default:"1" description:"Number of send goroutines to use"`
	Receivers                 int            `short:"n" long:"receivers" default:"32" description:"Number of receive goroutines to use. Max 256 and it has to be power of 2"`
	ReceiverBufferSize        int            `short:"B" long:"receiver-buffer-size" default:"134217728" description:"Accumulative pcap handler buffer size in bytes. It has to be power of 2. (default is 128MB)"`
	OutputChanBufferSize      int            `long:"output-chan-buffer-size" default:"1000000" description:"Buffer size for the channel being used for the output handler"`
	SourceAddress             string         `short:"S" long:"source-ip" description:"Source address for scan packets"`
	SourceInterface           string         `short:"i" long:"interface" description:"The outgoing network interface to use"`
	SourceGateway             string         `short:"g" long:"gateway-mac" description:"The outgoing gateway MAC address to use"`
	CooldownTime              int            `short:"c" long:"cooldown-time" default:"8" value-name:"secs" description:"how long to continue receiving after sending last probe in seconds"`
	TargetPort                int            `short:"p" long:"target-port" default:"-1" description:"Port number to scan (for TCP scans)"`
	SourcePort                string         `long:"source-port" default:"32768-61000" description:"Source port|range. Ex. 32768 or 32768-61000"`
	Probes                    int            `long:"probes" default:"1" description:"Number of probes to send each target"`
	Retries                   int            `long:"retries" default:"10" description:"Max number of times to try to send packet if send fails"`
	Flush                     bool           `long:"flush" description:"Flush after each line of output"`
	Expanded                  bool           `long:"expanded" description:"Output active IPv6 addresses in expanded format"`
	GOMAXPROCS                int            `long:"gomaxprocs" default:"0" description:"Set GOMAXPROCS"`
	IsIPv4                    bool           `long:"ipv4" description:"Run for IPv4"`
	Simulation                bool           `long:"simulation" description:"Simulate the hitrate without sending the packets"`
	SimulationHitrate         float32        `long:"simulation-hitrate" default:"10.0" description:"Hitrate percentage for the simulation. Supports up to two decimal points"`
	SourcePortFirst           uint16
	SourcePortLast            uint16
	Gateway                   net.HardwareAddr
	IFace                     *net.Interface
	SrcIP                     net.IP
}

// ModuleCommand stores a summary information of each module
type ModuleCommand struct {
	Command   string
	ShortDesc string
	LongDesc  string
	Data      interface{}
}

// ParseCommandLine parses the commands given on the command line
// and validates the framework configuration (global options)
// immediately after parsing
func ParseCommandLine(conf *Config, args []string, commands []ModuleCommand) ([]string, string) {
	parser := flags.NewParser(conf, flags.Default)
	for _, cmd := range commands {
		parser.AddCommand(cmd.Command, cmd.ShortDesc, cmd.LongDesc, cmd.Data)
	}
	conf.ConfigFileName = func(s string) {
		iniParser := flags.NewIniParser(parser)
		if s != "-" {
			if err := iniParser.ParseFile(s); err != nil {
				log.Fatalf("error while parsing ini file: %s", err)
			}
		} else {
			if err := iniParser.Parse(os.Stdin); err != nil {
				log.Fatalf("error while parsing ini from STDIN: %s", err)
			}
		}
	}

	posArgs, err := parser.ParseArgs(args)
	var cmd string = ""
	if err == nil {
		validateFrameworkConfiguration(conf)
		if parser.Command.Active != nil {
			cmd = parser.Command.Active.Name
		} else {
			log.Fatal("cannot get the command name after parsing")
			os.Exit(0)
		}
	}
	if err != nil {
		// Outputting help is returned as an error. Exit successfuly on help output.
		flagsErr, ok := err.(*flags.Error)
		if ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}

		// Didn't output help. Unknown parsing error.
		log.Fatalf("could not parse flags: %s", err)
	}
	return posArgs, cmd
}

// GetDeepCopyConfig parses a Config object and
// returns a duplicate of the same config in a
// different pointer. Useful for other go programs
// importing the scanner.
func GetDeepCopyConfig(val *Config) *Config {
	if val == nil {
		return nil
	}
	dup, err := copystructure.Copy(val)
	if err != nil {
		log.Fatal("cannot create a deep copy of given config")
	}
	validateFrameworkConfiguration(dup.(*Config))
	return dup.(*Config)
}

// GetFilename returns the filename (path) from the
// global configuration.
func GetFilename(config *Config, fileType string) string {
	switch fileType {
	case "log":
		return config.LogFileName
	case "input":
		return config.InputFileName
	case "output":
		return config.OutputFileName
	case "metadata":
		return config.MetaFileName
	default:
		log.Fatalf("cannot return filename for this file type %s", fileType)
	}
	return ""
}

// GetFile returns the file object from the
// global configuration.
func GetFile(config *Config, fileType string) *os.File {
	switch fileType {
	case "log":
		if config.LogFileName == "-" {
			return os.Stderr
		} else {
			var logFile *os.File
			var err error
			if logFile, err = os.Create(config.LogFileName); err != nil {
				log.Fatal(err)
			}
			log.Infof("log file is set to %s", config.LogFileName)
			log.SetOutput(logFile)
			return logFile
		}
	case "input":
		if config.InputFileName == "-" {
			return os.Stdin
		} else {
			var inputFile *os.File
			var err error
			if inputFile, err = os.Open(config.InputFileName); err != nil {
				log.Fatal(err)
			}
			return inputFile
		}
	case "output":
		if config.OutputFileName == "-" {
			return os.Stdout
		} else {
			var outputFile *os.File
			var err error
			if outputFile, err = os.Create(config.OutputFileName); err != nil {
				log.Fatal(err)
			}
			return outputFile
		}
	case "metadata":
		if config.MetaFileName == "-" {
			return os.Stderr
		} else {
			var metaFile *os.File
			var err error
			if metaFile, err = os.Create(config.MetaFileName); err != nil {
				log.Fatal(err)
			}
			return metaFile
		}
	default:
		return nil
	}
}

// validateFrameworkConfiguration validates if the provided arguments
// are actually correct and within the boundaries. It also initializes
// some settings such as the first and the last source port for the port
// range.
func validateFrameworkConfiguration(config *Config) {
	// et the logging output
	if config.LogFileName != "-" {
		log.SetOutput(GetFile(config, "log"))
	}

	// validate Go Runtime config
	if config.GOMAXPROCS < 0 {
		log.Fatalf("invalid GOMAXPROCS (must be positive, given %d)", config.GOMAXPROCS)
	}
	runtime.GOMAXPROCS(config.GOMAXPROCS)

	// parse the source port range
	var err error
	dash := strings.Split(config.SourcePort, "-")
	if len(dash) > 2 {
		log.Fatalf("source port range contains more than one '-' character: %s", config.SourcePort)
	} else if len(dash) == 2 { // Range
		var srcPortFirst int
		var srcPortLast int
		if srcPortFirst, err = strconv.Atoi(dash[0]); err != nil {
			log.Fatalf("cannot parse the first port to an integer: %s", dash[0])
		}
		utility.EnforceRange("starting source-port", srcPortFirst, 0, 0xFFFF)
		config.SourcePortFirst = uint16(srcPortFirst)
		if srcPortLast, err = strconv.Atoi(dash[1]); err != nil {
			log.Fatalf("cannot parse the last port to an integer: %s", dash[1])
		}
		utility.EnforceRange("ending source-port", srcPortLast, 0, 0xFFFF)
		config.SourcePortLast = uint16(srcPortLast)
		if config.SourcePortFirst > config.SourcePortLast {
			log.Fatalf("%s: invalid source port range: last port is less than first port.", config.SourcePort)
		}
	} else { // Single port
		var port int
		if port, err = strconv.Atoi(config.SourcePort); err != nil {
			log.Fatalf("cannot parse the source port to an integer: %s", config.SourcePort)
		}
		utility.EnforceRange("source-port", port, 0, 0xFFFF)
		config.SourcePortFirst = uint16(port)
		config.SourcePortLast = uint16(port)
	}
	if config.TargetPort != -1 {
		utility.EnforceRange("target-port", config.TargetPort, 0, 0xFFFF)
	}

	// parse hardware related things
	if config.SourceInterface == "" {
		log.Fatal("user has to set a source interface")
	}
	iface, err := net.InterfaceByName(config.SourceInterface)
	if err != nil {
		log.Fatalf("cannot parse the interface name: %s; Error: %s", config.SourceInterface, err)
	}
	config.IFace = iface

	if config.SourceGateway == "" {
		log.Fatal("user has to set a source gateway")
	}
	gateway, err := net.ParseMAC(config.SourceGateway)
	if err != nil {
		log.Fatalf("cannot parse the gateway address: %s; Error: %s", config.SourceGateway, err)
	}
	config.Gateway = gateway

	// TODO: Multiple Source Addresses
	if config.SourceAddress == "" {
		log.Fatal("user has to set a source address")
	}
	laddr := net.ParseIP(config.SourceAddress)
	if laddr == nil {
		log.Fatalf("cannot parse the source address (%s)", config.SourceAddress)
	}
	config.SrcIP = laddr

	// validate senders, receivers and the receivers accumulative buffer size
	if config.Senders <= 0 {
		log.Fatalf("need at least one sender, given %d", config.Senders)
	}

	if config.Receivers <= 0 {
		log.Fatalf("need at least one receiver, given %d", config.Receivers)
	}

	if config.Receivers > 256 {
		log.Fatal("too many receivers")
	}

	if (config.Receivers & (config.Receivers - 1)) != 0 {
		log.Fatal("number of receivers must be a power of 2")
	}

	if (config.ReceiverBufferSize & (config.ReceiverBufferSize - 1)) != 0 {
		log.Fatal("receiver accumulative buffer size must be a power of 2")
	}

	if config.OutputChanBufferSize <= 0 {
		log.Fatalf("output channel buffer size is set to 0 or lower (%d)", config.OutputChanBufferSize)
	}

	if config.ReceiverBufferSize < config.Receivers {
		log.Warnf("%d pcap buffer size is less than number of receivers. It is set to 1 byte each per receiver go routine (%d)", config.ReceiverBufferSize,
			config.Receivers)
		config.ReceiverBufferSize = config.Receivers
	}
	log.Infof("pcap buffer size per receiver go routines are set to %d bytes", config.ReceiverBufferSize/config.Receivers)

	if config.Simulation {
		if config.SimulationHitrate < 0.0 {
			config.SimulationHitrate = 0.0
		} else if config.SimulationHitrate > 100.0 {
			config.SimulationHitrate = 100.0
		}
		log.Infof("simulation is set to %.2f%% hitrate", config.SimulationHitrate)
	}
}
