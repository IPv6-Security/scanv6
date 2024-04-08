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
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"scanv6/config"
	"scanv6/utility"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// appendToDetailedOutput reads the detailed outputs from modules
// and writes them to the detailed output file.
func appendToDetailedOutput(outputPath string, outputs chan string,
	detailedOutputDone, detailedOutputReady *sync.WaitGroup) {
	defer detailedOutputDone.Done()
	f, err := os.OpenFile(outputPath,
		os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Infof("error while creating detailed output file: %s", err)
	}
	defer f.Close()
	detailedOutputReady.Done()
	for output := range outputs {
		if _, err := f.WriteString(fmt.Sprintf("%s\n", output)); err != nil {
			log.Infof("error while writing detailed output: %s", err)
		}
	}
}

// InitDetailedOutput initializes the output environment
// for detailed output task.
func InitDetailedOutput() (*sync.WaitGroup, chan string) {
	if conf.DetailedOutput != "" {
		var detailedOutputDone = new(sync.WaitGroup)
		var detailedOutputReady = new(sync.WaitGroup)
		detailedOutputPath := conf.DetailedOutput
		detailedOutputChan := make(chan string, 1000000)
		detailedOutputDone.Add(1)
		detailedOutputReady.Add(1)

		go appendToDetailedOutput(detailedOutputPath,
			detailedOutputChan,
			detailedOutputDone,
			detailedOutputReady)
		detailedOutputReady.Wait()
		log.Info("detailed output goroutine is ready")

		return detailedOutputDone, detailedOutputChan
	}
	return nil, nil
}

// InitICMPv6DestUnreachableOutput initializes the output environment
// for logging the ICMPv6 Destination Unreachables.
func InitICMPv6DestUnreachableOutput() (*sync.WaitGroup, chan string) {
	if conf.ICMPDestUnreachableOutput != "" {
		var outputDone = new(sync.WaitGroup)
		var outputReady = new(sync.WaitGroup)
		outputPath := conf.ICMPDestUnreachableOutput
		outputChan := make(chan string, 1000000)
		outputDone.Add(1)
		outputReady.Add(1)

		go appendToDetailedOutput(outputPath,
			outputChan,
			outputDone,
			outputReady)
		outputReady.Wait()
		log.Info("icmpv6 destination unreachables goroutine is ready")

		return outputDone, outputChan
	}
	return nil, nil
}

// InitMetadataOutput initializes the output environment
// for metadata output task.
func InitMetadataOutput() (*sync.WaitGroup, chan interface{}) {
	metadataOutputDone := new(sync.WaitGroup)
	metadataOutputReady := new(sync.WaitGroup)
	metadataOutputQueue := make(chan interface{}, 1000000)
	metadataOutputDone.Add(1)
	metadataOutputReady.Add(1)
	go func() {
		w := bufio.NewWriter(config.GetFile(conf, "metadata"))
		defer w.Flush()
		defer metadataOutputDone.Done()
		log.Info("metadata output goroutine is ready")
		metadataOutputReady.Done()
		for output := range metadataOutputQueue {
			byteRes, err := json.Marshal(output)
			if err != nil {
				log.Fatalf("unable to marshal data: %s", err)
			}
			if _, err := w.Write(byteRes); err != nil {
				log.Fatalf("cannot write to metadatafile: %s", err)
			}
			if err := w.WriteByte('\n'); err != nil {
				log.Fatalf("cannot write to metadatafile: %s", err)
			}
		}
		log.Info("metadata output goroutine terminates")
	}()
	metadataOutputReady.Wait()
	return metadataOutputDone, metadataOutputQueue
}

// InitOutput initializes the output environment
// for global scan results.
func InitOutput(mon *Monitor) (*sync.WaitGroup, chan net.IP) {
	outputDone := new(sync.WaitGroup)
	outputReady := new(sync.WaitGroup)
	outputQueue := make(chan net.IP, conf.OutputChanBufferSize)
	outputDone.Add(1)
	outputReady.Add(1)
	prob_source := rand.NewSource(time.Now().UnixNano())
	prob_rand := rand.New(prob_source)
	go func() {
		outputBuf := bufio.NewWriter(config.GetFile(conf, "output"))
		defer outputBuf.Flush()
		defer outputDone.Done()
		log.Info("output goroutine is ready")
		outputReady.Done()
		for srcIP := range outputQueue {
			if conf.Simulation {
				prob := prob_rand.Intn(10000)
				if prob >= int(100.0*conf.SimulationHitrate) {
					continue
				} else {
					mon.statusesChan <- statusSuccess
				}
			}
			var srcIPStr string
			if conf.Expanded && isIPv6 {
				srcIPStr = utility.Explode(srcIP)
			} else {
				srcIPStr = srcIP.String()
			}
			if _, err := outputBuf.Write([]byte(srcIPStr)); err != nil {
				log.Fatalf("error while writing source ip: %s", err)
			}
			if err := outputBuf.WriteByte('\n'); err != nil {
				log.Fatal(err)
			}
			if conf.Flush {
				outputBuf.Flush()
			}
		}
		log.Info("output goroutine terminates")
	}()
	outputReady.Wait()
	return outputDone, outputQueue
}
