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
package bin

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"scanv6"
	"scanv6/config"
)

var conf *config.Config

// Some parts of this code is modified from:
// https://github.com/zmap/zgrab2/blob/178d984996c518848e8c1133b6ce52ffaa621579/bin/bin.go

// Get the value of the SCANV6_MEMPROFILE variable (or the empty string).
// This may include {TIMESTAMP} or {NANOS}, which should be replaced using
// getFormattedFile().
func getMemProfileFile() string {
	return os.Getenv("SCANV6_MEMPROFILE")
}

// Get the value of the SCANV6_CPUPROFILE variable (or the empty string).
// This may include {TIMESTAMP} or {NANOS}, which should be replaced using
// getFormattedFile().
func getCPUProfileFile() string {
	return os.Getenv("SCANV6_CPUPROFILE")
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

// If CPU profiling is enabled (SCANV6_CPUPROFILE is not empty), start tracking
// CPU profiling in the configured file. Caller is responsible for invoking
// stopCPUProfile() when finished.
func startCPUProfile() {
	if file := getCPUProfileFile(); file != "" {
		now := time.Now()
		fullFile := getFormattedFile(file, now)
		f, err := os.Create(fullFile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
	}
}

// If CPU profiling is enabled (SCANV6_CPUPROFILE is not empty), stop profiling
// CPU usage.
func stopCPUProfile() {
	if getCPUProfileFile() != "" {
		pprof.StopCPUProfile()
	}
}

// SetConfigAndInit can be used to pass an actual config file to
// scanner itself. An example use case can be importing
// scanner in a different go program which parses
// its own config object. Thus, it can just pass this to the scanner.
func SetConfigAndInit(val *config.Config) {
	if val != nil {
		conf = nil
		conf = config.GetDeepCopyConfig(val)
	}
	dup := config.GetDeepCopyConfig(val)
	scanv6.SetConfigAndInit(dup)
}

// Scanv6Main sets the profiling functions, parses the command line
// arguments and initiates the scanning process.
func Scanv6Main(args []string, mcmds []config.ModuleCommand) {
	startCPUProfile()
	defer stopCPUProfile()
	defer dumpHeapProfile()
	conf = new(config.Config)
	_, _ = config.ParseCommandLine(conf, args, mcmds)
	scanv6.Process(args)
}
