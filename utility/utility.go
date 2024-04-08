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
package utility

/*
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

// Taken From: https://github.com/zmap/zmap/blob/118b910aefbd554e6e53337274cdf6dab617e857/lib/util.c#L352
double steady_now(void)
{
#if defined(_POSIX_TIMERS) && defined(_POSIX_MONOTONIC_CLOCK)
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return (double)tp.tv_sec + (double)tp.tv_nsec / 1000000000.;
#else
	struct timeval now;
	gettimeofday(&now, NULL);
	return (double)now.tv_sec + (double)now.tv_usec / 1000000.;
#endif
}
*/
import "C"

import (
	"fmt"
	"net"
	"os"

	log "github.com/sirupsen/logrus"
)

// // Returns the epoch time in seconds
// func now() float64 {
// 	now := time.Now()
// 	return float64(now.Second()) + float64(now.Nanosecond())/1000000000.0
// }

// Returns the epoch time in seconds
func Now() float64 {
	return float64(C.steady_now())
}

func check_range(v, min, max int) int {
	if v < min || v > max {
		return 0
	}
	return 1
}

func EnforceRange(name string, v, min, max int) {
	if check_range(v, min, max) == 0 {
		log.Fatalf("argument '%s' must be between %d and %d", name, min, max)
		os.Exit(1)
	}
}

func Explode(ip net.IP) string {
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
}
