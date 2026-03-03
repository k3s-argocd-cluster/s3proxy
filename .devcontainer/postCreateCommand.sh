#!/bin/bash
apt-get update
apt-get install -y --no-install-recommends git ssh curl unzip zsh bat

curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin latest

go install -v github.com/go-delve/delve/cmd/dlv@latest