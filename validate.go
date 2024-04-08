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
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	_ "crypto/sha256"
	"net"

	log "github.com/sirupsen/logrus"
)

const (
	HMAC_KEY_BYTES = 64
)

var initiated int = 0
var key []byte

// validateInit initializes the validation key randomly
func validateInit() {
	key = make([]byte, HMAC_KEY_BYTES)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal("couldn't get random bytes for validate")
	}
	initiated = 1
}

// validationGen generates validation bits from the given
// source and destination IPs
func validateGen(src, dst net.IP) []byte {
	if initiated != 1 {
		log.Fatal("validation algorithm is not initiated")
	}
	src = src.To16()
	dst = dst.To16()
	hash := hmac.New(crypto.SHA256.New, key)
	hash.Write(src)
	hash.Write(dst)
	sum := hash.Sum(nil)
	if len(sum) != 32 {
		log.Fatalf("validation couldn't generate enough bytes; have %d, want 32", len(sum))
	}
	return sum
}
