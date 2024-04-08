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
// https://github.com/zmap/zgrab2/blob/178d984996c518848e8c1133b6ce52ffaa621579/processing.go

package scanv6

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"scanv6/config"
	"scanv6/modules"

	log "github.com/sirupsen/logrus"
)

var moduleName string
var probeModule modules.Module
var conf *config.Config
var version int
var isIPv6 bool = true

type InitScannerStruct struct {
	ProcessQueue              chan net.IP
	CooldownFinished          chan bool
	OutputQueue               chan net.IP
	MetadataOutputQueue       chan interface{}
	DetailedOutputChan        chan string
	ICMPDestUnreachOutputChan chan string
	WorkerDone                *sync.WaitGroup
	RecvDone                  *sync.WaitGroup
	OutputDone                *sync.WaitGroup
	MetadataOutputDone        *sync.WaitGroup
	DetailedOutputDone        *sync.WaitGroup
	ICMPDestUnreachOutputDone *sync.WaitGroup
}

// Get the value of the SCANV6_MEMPROFILE variable (or the empty string).
// This may include {TIMESTAMP} or {NANOS}, which should be replaced using
// getFormattedFile().
func getMemProfileFile() string {
	return os.Getenv("SCANV6_MEMPROFILE")
}

// Replace instances in formatString of {TIMESTAMP} with when formatted as
// YYYYMMDDhhmmss, and {NANOS} as the decimal nanosecond offset.
func getFormattedFile(formatString string, when time.Time) string {
	timestamp := when.Format("20060102150405")
	nanos := fmt.Sprintf("%d", when.Nanosecond())
	ret := strings.Replace(formatString, "{TIMESTAMP}", timestamp, -1)
	ret = strings.Replace(ret, "{NANOS}", nanos, -1)
	return ret
}

// If memory profiling is enabled (SCANV6_MEMPROFILE is not empty), perform a GC
// then write the heap profile to the profile file.
func dumpHeapProfile() {
	if file := getMemProfileFile(); file != "" {
		now := time.Now()
		fullFile := getFormattedFile(file, now)
		f, err := os.Create(fullFile)
		if err != nil {
			log.Fatal("could not create heap profile: ", err)
		}
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write heap profile: ", err)
		}
		f.Close()
	}
}

// LoadConfigAndInit parses the command line arguments and
// sets the global config object accordingly.
func LoadConfigAndInit(args []string) {
	conf = new(config.Config)
	_, moduleName = config.ParseCommandLine(conf, args, modules.GetModuleCommands())
	probeModule, version = modules.GetModuleByName(moduleName)
	probeModule.SetFlags(modules.GetModuleFlags(probeModule.Name()))
	probeModule.ValidateFlags()
	_ = version
	isIPv6 = !conf.IsIPv4
	probeModule.Init()
	probeModule.ThreadInit()
}

// SetConfigAndInit creates a deep copy of the given configuration
// instance and points the global config to this new object.
// It also resets global variables.
func SetConfigAndInit(val *config.Config) *config.Config {
	if val != nil {
		conf = nil
		conf = config.GetDeepCopyConfig(val)
		probeModule, version = modules.GetModuleByName(moduleName)
		probeModule.SetFlags(modules.GetModuleFlags(probeModule.Name()))
		probeModule.ValidateFlags()
		isIPv6 = !conf.IsIPv4
		probeModule.Init()
		probeModule.ThreadInit()
		return conf
	}
	return nil
}

// InitScannerProcess initializes all of the components and
// returns the channels and wait groups for the corresponding components.
func InitScannerProcess(mon *Monitor, capacity, outputChanCapacity int, isSimulation bool, simulationHitrate float32) *InitScannerStruct {
	workers := conf.Senders
	processQueue := make(chan net.IP, capacity)
	cooldownFinished := make(chan bool, 1)

	metadataOutputDone, metadataOutputQueue := InitMetadataOutput()

	// Create wait groups
	workerDone := new(sync.WaitGroup)
	recvDone := new(sync.WaitGroup)
	var recvReady sync.WaitGroup
	workerDone.Add(int(workers))
	if !isSimulation {
		recvDone.Add(conf.Receivers)
		recvReady.Add(conf.Receivers)
	}

	SendInit()

	// Spawn the output goroutine
	outputDone, outputQueue := InitOutput(mon)
	detailedOutputDone, detailedOutputChan := InitDetailedOutput()
	icmpDestUnreachOutputDone, icmpDestUnreachOutputChan := InitICMPv6DestUnreachableOutput()

	// Spawn the recv thread
	if !isSimulation {
		pcapMutex := new(sync.Mutex)
		for i := 0; i < conf.Receivers; i++ {
			go func(shardID int) {
				defer recvDone.Done()
				RecvRun(shardID, pcapMutex, outputQueue, cooldownFinished, mon.statusesChan, &recvReady, metadataOutputQueue, detailedOutputChan, icmpDestUnreachOutputChan)
			}(i)
		}
		recvReady.Wait()
		log.Infof("%d receive go routines have been spawned", conf.Receivers)
	}

	// Call sender_run per worker
	// Start all the workers
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer workerDone.Done()
			sock := getSocket()
			SendRun(i, sock, processQueue, mon.statusesChan, mon.sendReady, metadataOutputQueue, isSimulation, outputQueue)
		}(i)
	}
	mon.sendReady.Wait()
	log.Infof("%d sender go routines have been spawned", workers)

	returnVariables := &InitScannerStruct{
		ProcessQueue:              processQueue,
		CooldownFinished:          cooldownFinished,
		WorkerDone:                workerDone,
		RecvDone:                  recvDone,
		OutputDone:                outputDone,
		OutputQueue:               outputQueue,
		MetadataOutputDone:        metadataOutputDone,
		MetadataOutputQueue:       metadataOutputQueue,
		DetailedOutputDone:        detailedOutputDone,
		DetailedOutputChan:        detailedOutputChan,
		ICMPDestUnreachOutputDone: icmpDestUnreachOutputDone,
		ICMPDestUnreachOutputChan: icmpDestUnreachOutputChan,
	}
	return returnVariables
}

// WrapUpScannerProcess ensures that we wait for packets on wire before
// we terminate the scan, and wait for all components to terminate and close channels.
func WrapUpScannerProcess(scanVariables *InitScannerStruct) {
	scanVariables.WorkerDone.Wait()
	log.Infof("all probes are sent")
	// No remaining inputs. Give Recv and monitoring thread to collect last bits of responses
	cdTime := time.Duration(conf.CooldownTime) * time.Second
	log.Infof("waiting %s for delayed responses", cdTime)
	time.Sleep(cdTime)
	if !conf.Simulation {
		for i := 0; i < conf.Receivers; i++ {
			scanVariables.CooldownFinished <- true
		}
		scanVariables.RecvDone.Wait()
		log.Info("recv goroutines are terminated")
	}
	close(scanVariables.OutputQueue)
	scanVariables.OutputDone.Wait()

	if scanVariables.DetailedOutputChan != nil && scanVariables.DetailedOutputDone != nil {
		close(scanVariables.DetailedOutputChan)
		log.Info("waiting for detailed output goroutine to finish")
		scanVariables.DetailedOutputDone.Wait()
	}

	if scanVariables.ICMPDestUnreachOutputChan != nil && scanVariables.ICMPDestUnreachOutputDone != nil {
		close(scanVariables.ICMPDestUnreachOutputChan)
		log.Info("waiting for icmpv6 dest unreachables output goroutine to finish")
		scanVariables.ICMPDestUnreachOutputDone.Wait()
	}
}

// Process sets up an output encoder, input reader, and starts grab workers.
func Process(args []string) {
	LoadConfigAndInit(args)

	wg := sync.WaitGroup{}
	mon := MakeMonitor(conf.Rate*conf.Senders*conf.Receivers, &wg)
	mon.Callback = func() {
		dumpHeapProfile()
	}
	log.Infof("monitoring go routine has been spawned")
	scanVariables := InitScannerProcess(mon, conf.Senders*conf.Rate, conf.OutputChanBufferSize, conf.Simulation, conf.SimulationHitrate)

	start := time.Now()
	log.Infof("started scan at %s", start.Format(time.RFC3339))

	go func() {
		if err := InputTargets(scanVariables.ProcessQueue, mon.GetStatusChan(), false, nil); err != nil {
			log.Fatal(err)
		}
	}()

	WrapUpScannerProcess(scanVariables)

	end := time.Now()
	log.Infof("finished scan at %s", end.Format(time.RFC3339))

	mon.Stop()
	wg.Wait()
	mode := "normal"
	if conf.Simulation {
		mode = fmt.Sprintf("simulation (exp. hit-rate: %.2f%%)", conf.SimulationHitrate)
	}
	s := Summary{
		Status:    mon.GetStatus(),
		Mode:      mode,
		StartTime: start.Format(time.RFC3339),
		EndTime:   end.Format(time.RFC3339),
		Duration:  end.Sub(start).String(),
	}
	scanVariables.MetadataOutputQueue <- s
	close(scanVariables.MetadataOutputQueue)
	scanVariables.MetadataOutputDone.Wait()
	scanVariables = nil
}
