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
	"sync"
	"syscall"
	"time"

	"scanv6/modules"
	"scanv6/utility"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// StateSend holds a summary of what happened
// in each sender goroutine
type StateSend struct {
	Type           string    `json:"type"`
	Start          time.Time `json:"start"`
	Finish         time.Time `json:"end"`
	HostsScanned   uint64    `json:"hosts_scanned"`
	PacketsSent    uint64    `json:"packets_sent"`
	SendtoFailures uint64    `json:"sendto_failures"`
	Complete       uint8     `json:"complete"`
}

var numOfSrcAddrs uint32
var numOfSrcPorts uint16

const (
	ETH_ALEN = 6 // Octets in one ethernet addr (taken from linux/if_ether.h)
)

// SendInit sets up the local variables for all sender goroutines
// and generates the key/sets up the validation generation component.
func SendInit() {
	numOfSrcAddrs = 1
	numOfSrcPorts = conf.SourcePortLast - conf.SourcePortFirst + 1
	es := ""
	if numOfSrcAddrs > 1 {
		es = "es"
	}
	log.Infof("will send from %d address%s on %d source ports", numOfSrcAddrs, es, numOfSrcPorts)

	validateInit()
}

// sendRunInit sets up the socket connection per sender goroutine.
func sendRunInit(sock int) unix.Sockaddr {
	sockAddrLL := &unix.SockaddrLinklayer{}
	ifreq, err := unix.NewIfreq(conf.IFace.Name)
	if err != nil {
		log.Fatalf("device interface name (%s) is too long; cannot initialize the sender thread", conf.IFace.Name)
	}
	if err := unix.IoctlIfreq(sock, unix.SIOCGIFINDEX, ifreq); err != nil {
		log.Error("SIOCGIFINDEX")
	}
	ifIndex := ifreq.Uint32()
	sockAddrLL.Ifindex = int(ifIndex)
	sockAddrLL.Halen = ETH_ALEN
	for i := 0; i < ETH_ALEN; i++ {
		sockAddrLL.Addr[i] = conf.Gateway[i]
	}
	return sockAddrLL
}

func sendPacket(sock int, to unix.Sockaddr, data []byte) error {
	return unix.Sendto(sock, data, 0, to)
}

// SendRun represents one sender goroutine. It also handles the
// rate limiting.
func SendRun(tid int, sock int, processQueue <-chan net.IP, statsCh chan status,
	sendReady *sync.WaitGroup, metadataOutputQueue chan interface{},
	isSimulation bool, outputQueue chan net.IP) int {
	sendStatus := &StateSend{
		Type:           fmt.Sprintf("send_status_%d", tid),
		PacketsSent:    0,
		HostsScanned:   0,
		Complete:       0,
		SendtoFailures: 0,
	}
	sendStatus.Start = time.Now()
	sockAddr := sendRunInit(sock)

	// get a separate copy of the same module per Sender Thread
	threadProbeModule, _ := modules.GetModuleByName(moduleName)
	threadProbeModule.SetFlags(modules.GetModuleFlags(moduleName))
	threadProbeModule.ValidateFlags()

	threadProbeModule.Init()
	threadProbeModule.ThreadInit()

	// adaptive timing to hit target rate
	var count uint64 = 0
	var lastCount uint64 = 0
	lastTime := utility.Now()
	var delay float64 = 0.0
	var interval int = 0
	var vi int
	ts := syscall.Timespec{}
	rem := syscall.Timespec{}

	var sendRate float64 = float64(conf.Rate) / float64(conf.Senders)
	var slowRate float64 = 50 // packets per seconds per thread at which it uses the slow methods

	nsecPerSec := time.Second.Nanoseconds()
	sleepTime := nsecPerSec

	if conf.Rate > 0 {
		delay = 10000.0
		if sendRate < slowRate {
			// Set the initial time difference
			sleepTime = nsecPerSec / int64(sendRate)
			lastTime = utility.Now() - (1.0 / float64(sendRate))
		} else {
			// Estimate the initial rate
			for vi = int(delay); vi != 0; vi-- {
			}
			delay *= 1.0 / (utility.Now() - lastTime) / (float64(conf.Rate) / float64(conf.Senders))
			interval = (conf.Rate / conf.Senders) / 20
			lastTime = utility.Now()
		}
	}
	sendReady.Done()

	// process each IP with adjusting the wait time between each send
	// operation
	for dstIP := range processQueue {
		sendStatus.HostsScanned++
		for i := 0; i < conf.Probes; i++ {
			if count != 0 && delay > 0.0 {
				if sendRate < slowRate {
					t := utility.Now()
					lastRate := (1.0 / (t - lastTime))
					sleepTime = int64(float64(sleepTime) * (((lastRate / sendRate) + 1.0) / 2.0))
					ts = syscall.Timespec{
						Sec:  sleepTime / nsecPerSec,
						Nsec: sleepTime % nsecPerSec,
					}
					log.Debugf("sleep for %d sec, %d nanoseconds", ts.Sec, ts.Nsec)
					err := syscall.Nanosleep(&ts, &rem)
					for err != nil {
						err = syscall.Nanosleep(&ts, &rem)
					}
					lastTime = t
				} else {
					for vi = int(delay); vi != 0; vi-- {
					}
					if interval == 0 || (count%uint64(interval) == 0) {
						t := utility.Now()
						multiplier := float64(count-lastCount) / (t - lastTime) / sendRate
						old_delay := delay
						delay *= multiplier
						if uint32(delay) == uint32(old_delay) {
							if multiplier > 1.0 {
								delay *= 2
							} else if multiplier < 1.0 {
								delay *= 0.5
							}
						}
						lastCount = count
						lastTime = t
					}
				}
			}
			count++
			// generate the validation bits and send the packet
			validation := validateGen(conf.SrcIP, dstIP)
			buf := threadProbeModule.MakePacket(i, dstIP, validation)
			for j := 0; j < conf.Retries; j++ {
				if isSimulation {
					outputQueue <- dstIP
					sendStatus.PacketsSent++
					statsCh <- statusTotal
					break
				} else {
					err := sendPacket(sock, sockAddr, buf)
					if err != nil {
						log.Debugf("send_packet failed for %s. err: %s", dstIP, err)
						sendStatus.SendtoFailures++
					} else {
						sendStatus.PacketsSent++
						statsCh <- statusTotal
						break
					}
				}
			}
		}
	}
	sendStatus.Complete = 1
	sendStatus.Finish = time.Now()
	metadataOutputQueue <- sendStatus
	return 0
}
