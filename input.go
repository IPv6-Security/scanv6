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
	"io"
	"net"
	"os"
	"strings"

	"scanv6/config"

	"github.com/netdata/go.d.plugin/pkg/iprange"
	log "github.com/sirupsen/logrus"
)

// Blocklist implements Tree for blocklisting
type Blocklist struct {
	pool iprange.Pool
}

// Contains returns if this IP belongs to any
// blocklisting range or not.
func (b Blocklist) Contains(ip net.IP) bool {
	return b.pool.Contains(ip)
}

// NewBlocklist creates a new blocklist tree from the
// blocklist file as given in filename parameter.
func NewBlocklist(filename string) Blocklist {
	ranges := make([]iprange.Range, 0)
	if filename == "" {
		return Blocklist{pool: ranges}
	}

	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer f.Close()
	log.Infof("going to use %s as blocklist.", filename)

	buf := bufio.NewReader(f)
	for {
		line, err := buf.ReadString('\n')
		if err == io.EOF {
			if line == "" {
				break
			}
		} else if err != nil {
			log.Errorf("error while reading blocklist address %s", err)
		}
		commentIndex := strings.Index(line, "#")
		stripped := line
		if commentIndex != -1 {
			stripped = line[:commentIndex]
		}
		trimmed := strings.TrimSpace(stripped)
		if trimmed == "" {
			continue
		}
		blockRange, err := iprange.ParseRange(trimmed)
		if err == nil {
			ranges = append(ranges, blockRange)
		} else {
			// Try as hostname
			log.Warnf("error while parsing blacklist range: '%s'; err: '%s'", trimmed, err)
			addrs, err := net.LookupHost(trimmed)
			if err == nil {
				for _, addr := range addrs {
					block, err := iprange.ParseRange(addr)
					if err == nil {
						log.Infoln("Found IP range for hostname", block, trimmed)
						ranges = append(ranges, block)
					}
				}
			} else {
				log.Warnf("lookup is unsuccessful, ignoring.")
			}
		}
	}
	return Blocklist{pool: ranges}
}

// InputTargets sets up the environment to read inputs from. It can be either a channel
// or a file.
func InputTargets(ch chan<- net.IP, statsCh chan status, readFromChannel bool, inputChannel chan net.IP) error {
	if readFromChannel && inputChannel == nil {
		log.Fatal("cannot set reading input channels for scanner")
	} else if readFromChannel && inputChannel != nil {
		log.Info("scanner input will be expected from a channel")
		return GetTargetsFromChan(inputChannel, NewBlocklist(conf.BlocklistFileName), ch, statsCh)
	}
	log.Info("scanner input will be expected from an input file")
	return GetTargetsFromFile(config.GetFile(conf, "input"), NewBlocklist(conf.BlocklistFileName), ch, statsCh)
}

// GetTargetsFromChan implements reading input from the given channel and
// sends them to the processing channel for sender goroutines.
func GetTargetsFromChan(inputChannel <-chan net.IP, blocklist Blocklist, ch chan<- net.IP, statsCh chan status) error {
	for target := range inputChannel {
		if target == nil {
			continue
		}
		if blocklist.Contains(target) {
			statsCh <- statusBlocked
			continue
		}
		ch <- target
	}
	close(ch)
	return nil
}

// GetTargetsFromFile reads input from a file. It considers inputs
// starting with # character as comments and ignores them.
func GetTargetsFromFile(source io.Reader, blocklist Blocklist, ch chan<- net.IP, statsCh chan status) error {
	addrBuf := bufio.NewReader(source)
	for {
		line, err := addrBuf.ReadString('\n')
		if err == io.EOF {
			if line == "" {
				// Close the channel -> there won't be any more inputs expected
				close(ch)
				break
			}
		} else if err != nil {
			// Close the channel -> there won't be any more inputs expected
			close(ch)
			return err
		}
		if line[0] != '#' {
			ip := net.ParseIP(strings.TrimSpace(line))
			if ip == nil {
				log.Warnf("%v was not a valid IP", line)
				continue
			}
			if blocklist.Contains(ip) {
				statsCh <- statusBlocked
				continue
			}
			ch <- ip
		}
	}
	return nil
}
