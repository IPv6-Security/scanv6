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
package main

import (
	"os"

	"scanv6/bin"
	"scanv6/modules"
)

// Some parts of this code is modified from:
// https://github.com/zmap/zgrab2/blob/178d984996c518848e8c1133b6ce52ffaa621579/cmd/zgrab2/main.go

// main function initializes the scanner and the modules
// with the given command line arguments
func main() {
	modules.LoadConfigAndInit(os.Args[1:])
	bin.Scanv6Main(os.Args[1:], modules.GetModuleCommands())
}
