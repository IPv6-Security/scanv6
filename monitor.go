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
// https://github.com/zmap/zgrab2/blob/178d984996c518848e8c1133b6ce52ffaa621579/monitor.go

package scanv6

import (
	"fmt"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Monitor is a collection of states per scans and a channel to communicate
// those scans to the monitor
type Monitor struct {
	state        *State
	statusesChan chan status
	sendReady    *sync.WaitGroup
	// Callback is invoked after each scan.
	Callback func()
}

// State contains the respective number of successes and failures
// for a given scan
type State struct {
	TotalProbes uint64  `json:"total_probes"`
	Successes   uint64  `json:"successes"`
	Blocked     uint64  `json:"blocked"`
	Dropped     uint64  `json:"dropped"`
	IfDropped   uint64  `json:"Ifdropped"`
	HitRate     float64 `json:"hitrate"`
}

type status uint

const (
	statusTotal     status = iota
	statusSuccess   status = iota
	statusBlocked   status = iota
	statusDropped   status = iota
	statusIfDropped status = iota
)

var finished chan bool

// GetStatuses returns a mapping from scanner names to the current number
// of successes and failures for that scanner
func (m *Monitor) GetStatus() *State {
	return m.state
}

// GetWaitGroup returns the wait group for sender goroutines ready or not.
func (m *Monitor) GetWaitGroup() *sync.WaitGroup {
	return m.sendReady
}

func (m *Monitor) GetStatusChan() chan status {
	return m.statusesChan
}

// Stop indicates the monitor is done and the internal channel should be closed.
// This function does not block, but will allow a call to Wait() on the
// WaitGroup passed to MakeMonitor to return.
func (m *Monitor) Stop() {
	finished <- true
	log.Info("monitoring is terminating")
	close(m.statusesChan)
}

// numberString is a helper function to turn numbers into humanreadable format.
func numberString(n float64) string {
	figs := 0
	if n < 1000 {
		return fmt.Sprintf("%.1f", n)
	} else if n < 1000000 {
		if n < 10000 {
			figs = 2
		} else if n < 100000 {
			figs = 1
		}
		return fmt.Sprintf("%0.*f K", figs, n/1000.0)
	} else {
		if figs < 10000000 {
			figs = 2
		} else if figs < 100000000 {
			figs = 1
		}
		return fmt.Sprintf("%0.*f M", figs, n/1000000.0)
	}
}

// reportRates is a helper function that gives scan status updates
// every second.
func reportRates(m *Monitor, reportReady *sync.WaitGroup) {
	var lastProbeCount uint64 = 0
	var lastHitCount uint64 = 0
	reportReady.Done()
	m.sendReady.Wait()
	var startTime time.Time = time.Now()
	var lastTickTime time.Time = time.Now()
	for {
		select {
		case <-finished:
			return
		default:
			hits := m.state.Successes
			blocked := m.state.Blocked
			dropped := m.state.Dropped
			ifDropped := m.state.IfDropped
			probes := m.state.TotalProbes
			hitRate := m.state.HitRate
			now := time.Now()
			timePassedSinceLastTick := now.Sub(lastTickTime).Seconds()
			timePassedSinceStart := now.Sub(startTime).Seconds()
			if 1.2 < timePassedSinceLastTick {
				log.Warnf("Took longer than a second (%.2fs) since last tick",
					timePassedSinceLastTick,
				)
			}
			log.Infof("%.3f%% hit rate; (%s pps avg.) %d probes sent (m+: %d); dropped: (%d | if: %d); "+
				"(%s pps avg.) %d hits received (m+: %d); "+
				"%d addresses blocked; [t+: %.4fs]\n",
				hitRate, numberString(float64(probes)/timePassedSinceStart), probes, probes-lastProbeCount, dropped, ifDropped,
				numberString(float64(hits)/timePassedSinceStart), hits, hits-lastHitCount, blocked, timePassedSinceLastTick)

			multiplier := 1.5
			if conf.Rate <= 5 {
				multiplier = 2.0
			}
			if float64(probes-lastProbeCount) > multiplier*(timePassedSinceLastTick*float64(conf.Rate)) {
				log.Fatal("sent packets more than 1.5 x RATE. terminating...")
				os.Exit(1)
			}
			lastProbeCount = probes
			lastHitCount = hits
			lastTickTime = now
			time.Sleep(1 * time.Second)
		}
	}
}

// MakeMonitor returns a Monitor object that can be used to collect and send
// the status of a running scan
func MakeMonitor(statusChanSize int, wg *sync.WaitGroup) *Monitor {
	m := new(Monitor)
	m.statusesChan = make(chan status, statusChanSize)
	if m.state == nil {
		m.state = new(State)
	}
	finished = make(chan bool, 1)
	m.sendReady = &sync.WaitGroup{}
	wg.Add(1)
	m.sendReady.Add(conf.Senders)
	reportReady := &sync.WaitGroup{}
	reportReady.Add(1)
	go reportRates(m, reportReady)
	reportReady.Wait()
	go func() {
		defer wg.Done()
		for s := range m.statusesChan {
			if m.Callback != nil {
				m.Callback()
			}
			switch s {
			case statusSuccess:
				m.state.Successes++
			case statusTotal:
				m.state.TotalProbes++
			case statusBlocked:
				m.state.Blocked++
			case statusDropped:
				m.state.Dropped++
			case statusIfDropped:
				m.state.IfDropped++
			default:
				continue
			}
			m.state.HitRate = 100.0 * float64(m.state.Successes) / float64(m.state.TotalProbes)
		}
	}()
	return m
}
