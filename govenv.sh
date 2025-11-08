#!/bin/bash
mkdir -p go/ponalyzer_venv
export GOPATH=$(pwd)/go/ponalyzer_venv/.gocache
export GOMODCACHE=$GOPATH/pkg/mod
export GOCACHE=$GOPATH/build
export GOBIN=$GOPATH/bin
export PATH=$GOBIN:$PATH
echo "Go environment isolated at $GOPATH"
echo "To reset the Go environmant back to system settings use a different bash session"
