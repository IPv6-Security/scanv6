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
package scanv6

import (
	"fmt"
	"net"
	"scanv6/modules"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
)

// StateRecv holds a summary of what happened
// in each receiver goroutine
type StateRecv struct {
	Type             string    `json:"type"`
	Start            time.Time `json:"start"`
	Finish           time.Time `json:"end"`
	ValidationPassed uint64    `json:"validation_passed"`
	ValidationFailed uint64    `json:"validation_failed"`
	ProcessPassed    uint64    `json:"process_passed"`
	ProcessFailed    uint64    `json:"process_failed"`
	Complete         uint8     `json:"complete"`
}

const (
	PCAP_PROMISC     = true
	PCAP_SNAPLEN     = 4096
	PCAP_TIMEOUT     = 100
	PCAP_IMMIDIATE   = true
	PCAP_BUFFER_SIZE = 100 * 1024 * 1024
)

// ReceiverPacketParser is used for parsing received packets
// up to IP layer.
type ReceiverPacketParser struct {
	eth     *layers.Ethernet
	ip6     *layers.IPv6
	payload gopacket.Payload
	decoded *[]gopacket.LayerType
	parser  *gopacket.DecodingLayerParser
}

// MakeNewModulePacketParser returns a fresh packet parser for
// modules
func MakeNewReceiverPacketParser() *ReceiverPacketParser {
	recvParser := &ReceiverPacketParser{
		eth:     &layers.Ethernet{},
		ip6:     &layers.IPv6{},
		payload: gopacket.Payload{},
		decoded: new([]gopacket.LayerType),
		parser:  nil,
	}
	recvParser.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, recvParser.eth, recvParser.ip6, &recvParser.payload)
	recvParser.parser.IgnoreUnsupported = true // ignore `No decoder for layer type ICMPv6RouterAdvertisement` error
	return recvParser
}

// handlePacket handles one packet at a time and updates the state.
// It also sends the information to detailed output channel if set,
// and the positive IPs to the output channel.
func handlePacket(recvParser *ReceiverPacketParser, threadProbeModule modules.Module, recvStatus *StateRecv,
	outputQueue chan net.IP, data []byte, statsCh chan status,
	detailedOutputChan, icmpDestUnreachOutputChan chan string) {
	var dstIP net.IP
	var srcIP net.IP
	var validation []byte

	recvTime := time.Now()
	err := recvParser.parser.DecodeLayers(data, recvParser.decoded)
	if err != nil {
		log.Debugf("error decoding packet: %s", err)
		return
	}
	// parse packet into the probe module instance
	err = threadProbeModule.ParsePacket(data)
	if err != nil {
		log.Debugf("parsing packet in recv threadProbeModule failed for %s", srcIP)
		return
	}

	// generate the validation bytes for encryption
	srcIP = recvParser.ip6.SrcIP
	dstIP = recvParser.ip6.DstIP
	validation = validateGen(dstIP, srcIP)

	// this should validate if the packet is a response to our scan
	if threadProbeModule.ValidatePacket(data, srcIP, dstIP, validation, recvTime, icmpDestUnreachOutputChan) {
		recvStatus.ValidationPassed++
	} else {
		recvStatus.ValidationFailed++
		return
	}

	// process packet with the module then mark it as success or not
	if threadProbeModule.ProcessPacket(data, validation) {
		recvStatus.ProcessPassed++
		outputQueue <- srcIP
		if conf.DetailedOutput != "" && detailedOutputChan != nil {
			if detailedOutput := threadProbeModule.GetDetailedOutputOfPacket(true, recvTime, validation); detailedOutput != "" {
				detailedOutputChan <- detailedOutput
			}
		}
		statsCh <- statusSuccess
	} else {
		recvStatus.ProcessFailed++
	}
}

// RecvRun represents one receiver goroutine. It handles pcap listening
// and packet classification.
func RecvRun(shardID int, pcapMutex *sync.Mutex, outputQueue chan net.IP, cooldownFinished chan bool,
	statsCh chan status, wg *sync.WaitGroup, metadataOutputQueue chan interface{},
	detailedOutputChan, icmpDestUnreachOutputChan chan string) int {
	if outputQueue == nil {
		log.Fatalf("output queue is not set for receiver %d", shardID)
	}
	recvStatus := &StateRecv{
		Type:             fmt.Sprintf("recv_status_%d", shardID),
		ValidationPassed: 0,
		ValidationFailed: 0,
		ProcessPassed:    0,
		ProcessFailed:    0,
		Complete:         0,
	}

	// get a separate copy of the same module per Receiver Thread
	threadProbeModule, _ := modules.GetModuleByName(moduleName)
	threadProbeModule.SetFlags(modules.GetModuleFlags(moduleName))
	threadProbeModule.ValidateFlags()
	threadProbeModule.Init()
	threadProbeModule.ThreadInit()

	// get a separate copy of the parser per Receiver Thread
	recvParser := MakeNewReceiverPacketParser()

	recvStatus.Start = time.Now()

	// get the pcap listener and set it with the correct filter
	inactive, handle := GetPcapHandle(shardID, conf.SourceInterface,
		PCAP_SNAPLEN, conf.ReceiverBufferSize/conf.Receivers, PCAP_PROMISC, PCAP_IMMIDIATE,
		time.Duration(time.Millisecond*time.Duration(PCAP_TIMEOUT)))
	defer inactive.CleanUp()

	pcapMutex.Lock()
	filter := threadProbeModule.GetPcapFilter()
	filter += threadProbeModule.GetRecvShardFilter(shardID)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("cannot set BPF Filter for recv %d; err: %s", shardID, err)
	}
	handle.SetDirection(pcap.DirectionIn)
	pcapMutex.Unlock()

	// this is the goroutine to keep track of packet losses on the scanner side.
	scannerWrapup := new(bool)
	var dropMonitorDone = new(sync.WaitGroup)
	var dropMonitorReady = new(sync.WaitGroup)
	dropMonitorDone.Add(1)
	dropMonitorReady.Add(1)
	go func() {
		lastDropped := 0
		lastIfDropped := 0
		ticker := time.NewTicker(1 * time.Second)
		dropMonitorReady.Done()
		defer dropMonitorDone.Done()
		for range ticker.C {
			if *scannerWrapup {
				return
			}
			stats, _ := handle.Stats()
			for lastDropped != stats.PacketsDropped {
				statsCh <- statusDropped
				lastDropped++
			}
			for lastIfDropped != stats.PacketsIfDropped {
				statsCh <- statusIfDropped
				lastIfDropped++
			}
		}
	}()
	dropMonitorReady.Wait()

	// actual packet receive and processing happens in this for loop.
	wg.Done()
	for {
		select {
		case <-cooldownFinished:
			*scannerWrapup = true
			recvStatus.Finish = time.Now()
			recvStatus.Complete = 1
			dropMonitorDone.Wait()
			handle.Close()
			metadataOutputQueue <- recvStatus
			return 0
		default:
			// Read in the next packet.
			data, _, err := handle.ReadPacketData()
			if err == pcap.NextErrorTimeoutExpired {
				continue
			} else if err != nil {
				log.Fatal("RECV: Error reading pcap:", err.Error())
			} else {
				handlePacket(recvParser, threadProbeModule, recvStatus, outputQueue, data, statsCh, detailedOutputChan, icmpDestUnreachOutputChan)
			}
		}
	}
}
