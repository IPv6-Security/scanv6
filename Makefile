# Copyright 2024 Georgia Institute of Technology

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# 	http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ifeq ($(OS),Windows_NT)
  EXECUTABLE_EXTENSION := .exe
else
  EXECUTABLE_EXTENSION :=
endif

GO_FILES = $(shell find . -type f -name '*.go')
TEST_MODULES ?= 

all: build

test:
	cd lib/output/test && go test -v ./...
	cd modules && go test -v ./...

update: clean
	go clean -cache
	go clean -modcache
	go get -u all
	go mod tidy
	cd cmd/scanv6 && go build -a && cd ../..
	rm -f scanv6
	ln -s cmd/scanv6/scanv6$(EXECUTABLE_EXTENSION) scanv6

gofmt:
	goimports -w -l $(GO_FILES)

build: $(GO_FILES)
	cd cmd/scanv6 && go build && cd ../..
	rm -f scanv6
	ln -s cmd/scanv6/scanv6$(EXECUTABLE_EXTENSION) scanv6

build-all: $(GO_FILES)
	cd cmd/scanv6 && go build -a && cd ../..
	rm -f scanv6
	ln -s cmd/scanv6/scanv6$(EXECUTABLE_EXTENSION) scanv6

clean:
	cd cmd/scanv6 && go clean
	rm -f scanv6
