#!/bin/bash
source ./govenv.sh
cd src
GOPATH=$(pwd)/../go/ponalyzer_venv/.gocache GOMODCACHE=$(pwd)/../go/ponalyzer_venv/.gocache/pkg/mod GOCACHE=$(pwd)/../go/ponalyzer_venv/.gocache/build GOBIN=$(pwd)/../go/ponalyzer_venv/.gocache/bin PATH="$(pwd)/../go/ponalyzer_venv/.gocache/bin:$PATH" $(pwd)/../go/bin/go run .
