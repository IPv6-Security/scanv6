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
	"time"

	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
)

// GetPcapHandle returns a fresh pcap handler with the
// given settings
func GetPcapHandle(shardID int, iface string, snaplen int,
	bufferSize int, promisc, immidiate bool,
	timeout time.Duration) (*pcap.InactiveHandle, *pcap.Handle) {
	handle, err := pcap.NewInactiveHandle(iface)

	if err != nil {
		log.Fatalf("PCAP: Unable to create handle for recv %d", shardID)
	}

	err = handle.SetSnapLen(snaplen)
	if err != nil {
		log.Fatalf("PCAP: Unable to set snaplen for recv %d", shardID)
	}

	err = handle.SetPromisc(promisc)
	if err != nil {
		log.Fatalf("PCAP: Unable to set promisc mode for recv %d", shardID)
	}

	err = handle.SetImmediateMode(immidiate)
	if err != nil {
		log.Fatalf("PCAP: Unable to set immediate mode for recv %d", shardID)
	}

	err = handle.SetTimeout(timeout)
	if err != nil {
		log.Fatalf("PCAP: Unable to set timeout for recv %d", shardID)
	}

	ts, err := pcap.TimestampSourceFromString("adapter")
	if err != nil {
		log.Fatalf("PCAP: Unable to set adapter timestamp source for recv %d", shardID)
	}

	err = handle.SetTimestampSource(ts)
	if err != nil {
		log.Fatalf("PCAP: Unable to set timestamp source for recv %d", shardID)
	}

	err = handle.SetBufferSize(bufferSize)
	if err != nil {
		log.Fatalf("PCAP: Unable to set buffer size for recv %d", shardID)
	}

	activeHandle, err := handle.Activate()
	if err != nil {
		log.Fatalf("PCAP: Unable to activate handle for recv %d", shardID)
	}

	return handle, activeHandle
}
